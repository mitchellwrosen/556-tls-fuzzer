{-# LANGUAGE ScopedTypeVariables, TupleSections #-}

module Main where

import Control.Applicative
import Control.Concurrent         (ThreadId, killThread, threadDelay)
import Control.Concurrent.Suspend (Delay, sDelay)
import Control.Concurrent.Timer   (oneShotTimer)
import Control.Monad
import Control.Exception
import Crypto.Random
import Data.IORef
import Data.X509.CertificateStore (CertificateStore)
import Network.Simple.TCP
import Network.TLS
import Network.TLS.Struct
import System.Environment         (getArgs)
import System.IO
import System.X509                (getSystemCertificateStore)

import qualified Data.ByteString as BS

import ThreadManager
import Tls
import Utils

main :: IO ()
main = do
    args <- getArgs
    case args of
        [hostfile,numhosts] -> main' hostfile (read numhosts)
        _ -> hPutStrLn stderr "Usage: ./a.out hostfile numhosts"

main' :: String -> Int -> IO ()
main' hostfile numhosts = do
    hSetBuffering stderr NoBuffering

    threadManager <- newManager
    hosts         <- take numhosts . lines <$> readFile hostfile
    certStore     <- getSystemCertificateStore

    forM_ hosts (doWork threadManager certStore)
    waitAll threadManager >>= putStrLn . formatOutput
  where
    doWork :: ThreadManager (HostName,[CipherID]) -> CertificateStore -> HostName -> IO ThreadId
    doWork threadManager certStore host = do
        {-threadDelay 1000000-}
        tid <- fork threadManager $ getCiphersuites certStore host
        _ <- oneShotTimer (killThread tid) (sDelay 5)
        return tid

    formatOutput :: [FinishedThreadStatus (HostName,[CipherID])] -> String
    formatOutput = unlines . map formatOutput'
      where
        formatOutput' :: FinishedThreadStatus (HostName,[CipherID]) -> String
        formatOutput' (Left ex) = "FAILED: " ++ show ex
        formatOutput' (Right (host, cs)) = host ++ " " ++ show cs

getCiphersuites :: CertificateStore -> HostName -> IO (HostName,[CipherID])
getCiphersuites certStore host = do
    hPutStr stderr "."
    ciphersRef   <- newIORef allCiphersuites
    cipherIdsRef <- newIORef []
    loop certStore ciphersRef cipherIdsRef host
  where
    loop :: CertificateStore -> IORef [Cipher] -> IORef [CipherID] -> HostName -> IO (HostName,[CipherID])
    loop certStore ciphersRef cipherIdsRef host = do
        ciphers <- readIORef ciphersRef
        -- Have we tried all ciphers?
        if not (null ciphers)
            then catch
                (do
                    withContext host weakRng certStore ciphers $ \context -> do
                        contextHookSetHandshakeRecv context handshakeRecvHook
                        handshake context
                    loop certStore ciphersRef cipherIdsRef host)
                onError
            else makeReturnValue
      where
        -- We expect a TLSException if the server doesn't like any proposed ciphersuites.
        -- However, we propogate other exceptions (such as ThreadKilled)
        onError :: SomeException -> IO (HostName,[CipherID])
        onError e = maybe (throw e) (\_ -> makeReturnValue) (fromException e :: Maybe TLSException)

        makeReturnValue :: IO (HostName,[CipherID])
        makeReturnValue = (host,) <$> readIORef cipherIdsRef

        handshakeRecvHook :: Handshake -> IO Handshake
        handshakeRecvHook hs@(ServerHello _ _ _ cid _ _) = do
            modifyIORef' ciphersRef deleteSelectedCipher
            modifyIORef' cipherIdsRef (++ [cid])
            return hs
          where
            deleteSelectedCipher :: [Cipher] -> [Cipher]
            deleteSelectedCipher [] = []
            deleteSelectedCipher (x:xs)
                | cipherID x == cid = xs
                | otherwise = x : deleteSelectedCipher xs
        handshakeRecvHook hs = return hs
