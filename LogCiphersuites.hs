{-# LANGUAGE ScopedTypeVariables #-}

module Main where

import Control.Applicative
import Control.Exception
import Crypto.Random
import Data.IORef
import Data.X509.CertificateStore (CertificateStore)
import Network.Simple.TCP
import Network.TLS
import Network.TLS.Struct
import System.Environment (getArgs)
import System.IO
import System.X509 (getSystemCertificateStore)

import qualified Data.ByteString as BS

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
    hosts <- take numhosts . lines <$> readFile hostfile
    certStore <- getSystemCertificateStore
    let totalHosts = show (length hosts)

    forMn_ hosts $ \host n -> do
        hPutStr stderr $ "\n[" ++ show (n+1) ++ "/" ++ totalHosts ++ "] " ++ host ++ " "
        ciphersRef <- newIORef allCiphersuites
        putStr host
        loop1 certStore ciphersRef host
      where
        loop1 :: CertificateStore -> IORef [Cipher] -> HostName -> IO ()
        loop1 certStore ciphersRef host = do
            ciphers <- readIORef ciphersRef
            if not (null ciphers)
                then loop2 ciphers `catch` (\(_ :: SomeException) -> putStrLn "")
                else putStrLn ""
          where
            loop2 :: [Cipher] -> IO ()
            loop2 ciphers = do
                withContext host weakRng certStore ciphers $ \context -> do
                    contextHookSetHandshakeRecv context (handshakeRecvHook ciphersRef)
                    handshake context
                loop1 certStore ciphersRef host

handshakeRecvHook :: IORef [Cipher] -> Handshake -> IO Handshake
handshakeRecvHook ciphers hs@(ServerHello _ _ _ cid _ _) = do
    putStr $ ',' : show cid
    -- Remove the cipher the server selected and repeat.
    modifyIORef ciphers deleteSelectedCipher
    return hs
  where
    deleteSelectedCipher :: [Cipher] -> [Cipher]
    deleteSelectedCipher [] = []
    deleteSelectedCipher (x:xs)
        | cipherID x == cid = xs
        | otherwise = x : deleteSelectedCipher xs
handshakeRecvHook _ hs = return hs
