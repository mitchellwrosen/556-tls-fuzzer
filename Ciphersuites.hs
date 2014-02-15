{-# LANGUAGE ScopedTypeVariables, TupleSections #-}

module Main where

import Control.Applicative
import Control.Concurrent.ParallelIO.Local
import Control.Exception
import Data.IORef
import Data.X509.CertificateStore          (CertificateStore)
import Network.Simple.TCP
import Network.TLS
import Network.TLS.Struct
import Options.Applicative
import System.IO
import qualified System.Timeout as T
import System.X509                         (getSystemCertificateStore)

import Tls
import Utils

data Cli = Cli
    { cliNumThreads :: Int
    , cliDelay      :: Int
    , cliFrom       :: Maybe Int
    , cliTo         :: Maybe Int
    , cliHostfile   :: String
    }

cli :: Parser Cli
cli = Cli <$> numThreads <*> timeout <*> from <*> to <*> hostfile
  where
    numThreads :: Parser Int
    numThreads = option $
        short 'n' <>
        long "num-threads" <>
        help "The maximum number of threads to use." <>
        value 10 <>
        metavar "NUM-THREADS"

    timeout :: Parser Int
    timeout = option $
        short 't' <>
        long "timeout" <>
        help "The timeout (in seconds) before closing a connection." <>
        value 5 <>
        metavar "TIMEOUT"

    from :: Parser (Maybe Int)
    from = optional $ option $
        long "from" <>
        help "From host" <>
        metavar "FROM"

    to :: Parser (Maybe Int)
    to = optional $ option $
        long "to" <>
        help "To host" <>
        metavar "TO"

    hostfile :: Parser String
    hostfile = argument str $
        help "The file of hosts to connect to, one per line" <>
        metavar "HOSTS"

main :: IO ()
main = execParser opts >>= main'
  where
    opts = info (helper <*> cli) $
        fullDesc <>
        progDesc "Determine the ciphersuites accepted by HTTPS servers." <>
        header "Ciphersuite scraper"

main' :: Cli -> IO ()
main' (Cli numThreads timeout mfrom mto hostfile) = do
    hSetBuffering stderr NoBuffering

    let from = maybe 0 id mfrom

    hosts     <- maybe id (\to -> take (to-from)) mto . drop from . lines <$> readFile hostfile
    certStore <- getSystemCertificateStore

    parallelWithPoolOf numThreads (map (getCiphersuites timeout certStore) hosts)
        >>= putStrLn . formatOutput
  where
    formatOutput :: [(HostName,[CipherID])] -> String
    formatOutput = unlines . map formatOutput'
      where
        formatOutput' :: (HostName,[CipherID]) -> String
        formatOutput' (host, cs) = host ++ " " ++ show cs

parallelWithPoolOf :: Int -> [IO a] -> IO [a]
parallelWithPoolOf n as = withPool n (\pool -> parallel pool as)

getCiphersuites :: Int -> CertificateStore -> HostName -> IO (HostName,[CipherID])
getCiphersuites timeout certStore host = do
    hPutStr stderr "."
    ciphersRef   <- newIORef allCiphersuites
    cipherIdsRef <- newIORef []
    loop ciphersRef cipherIdsRef
  where
    loop :: IORef [Cipher] -> IORef [CipherID] -> IO (HostName,[CipherID])
    loop ciphersRef cipherIdsRef = do
        ciphers <- readIORef ciphersRef
        -- Have we tried all ciphers?
        if not (null ciphers)
            then catch
                (do
                    {-result <- T.timeout (timeout*1000000) $-}
                        withContext host weakRng certStore ciphers $ \context -> do
                            contextHookSetHandshakeRecv context handshakeRecvHook
                            handshake context
                        loop ciphersRef cipherIdsRef)
                    {-case result of-}
                        {-Nothing -> return (host,[]) -- timed out-}
                        {-Just _  -> loop ciphersRef cipherIdsRef)-}
                (\(_ :: SomeException) -> makeReturnValue)
            else makeReturnValue
      where
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
