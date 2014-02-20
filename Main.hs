{-# LANGUAGE ScopedTypeVariables, TupleSections #-}

module Main where

import           Control.Applicative
import           Control.Exception
import           Data.IORef
import           Data.X509.CertificateStore          (CertificateStore)
import           Network.Simple.TCP
import           Network.TLS
import           Network.TLS.Struct
import           Network.TLS.Types
import           Options.Applicative
import           System.IO
import qualified System.Timeout                      as T
import           System.X509                         (getSystemCertificateStore)
import           Text.ParserCombinators.ReadPrec     (lift)
import           Text.ParserCombinators.ReadP        (ReadP, (+++), string)
import           Text.Read                           (readPrec)

import Tls
import Utils                                         (parallelWithPoolOf)

data Metric
    = Ciphersuites
    | Compressions
    deriving Show

instance Read Metric where
    readPrec = lift (ciphersuites +++ compressions)
      where
        ciphersuites :: ReadP Metric
        ciphersuites = Ciphersuites <$ string "ciphersuites"

        compressions :: ReadP Metric
        compressions = Compressions <$ string "compressions"

data Cli = Cli
    { cliMetric     :: Metric
    , cliNumThreads :: Int
    , cliTimeout    :: Int
    , cliFrom       :: Maybe Int
    , cliTo         :: Maybe Int
    , cliHostfile   :: FilePath
    }

cli :: Parser Cli
cli = Cli <$> metric <*> numThreads <*> timeout <*> from <*> to <*> hostfile
  where
    metric :: Parser Metric
    metric = option $
        short 'm' <>
        long "metric" <>
        help "The metric to gather (\"ciphersuites\" or \"compressions\")" <>
        metavar "METRIC"

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
main = execParser opts >>= main2
  where
    opts = info (helper <*> cli) $
        fullDesc <>
        progDesc "Determine the ciphersuites accepted by HTTPS servers." <>
        header "Ciphersuite scraper"

main2 :: Cli -> IO ()
main2 (Cli metric numThreads timeout mfrom mto hostfile) = do
    hSetBuffering stderr NoBuffering

    let from = maybe 0 id mfrom

    hosts     <- maybe id (\to -> take (to-from)) mto . drop from . lines <$> readFile hostfile
    certStore <- getSystemCertificateStore

    main3 metric certStore hosts
  where
    main3 :: Metric -> CertificateStore -> [HostName] -> IO ()
    main3 Ciphersuites = main4 getCiphersuites
    main3 Compressions = main4 getCompressions

    main4 :: Show a
          => (Int -> CertificateStore -> HostName -> IO (HostName,a))
          -> CertificateStore
          -> [HostName]
          -> IO ()
    main4 getMetric certStore hosts =
        parallelWithPoolOf numThreads (map (getMetric timeout certStore) hosts) >>= putStrLn . formatOutput
      where
        formatOutput :: Show a => [(HostName,a)] -> String
        formatOutput = unlines . map formatOutput'
          where
            formatOutput' :: Show a => (HostName,a) -> String
            formatOutput' (host, cs) = host ++ " " ++ show cs

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
                    result <- T.timeout (timeout*1000000) $
                        withContext host weakRng certStore ciphers [nullCompression] $ \context -> do
                            contextHookSetHandshakeRecv context handshakeRecvHook
                            handshake context
                    case result of
                        Nothing -> return (host,[]) -- timed out
                        Just _  -> loop ciphersRef cipherIdsRef)
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

getCompressions :: Int -> CertificateStore -> HostName -> IO (HostName,[CompressionID])
getCompressions timeout certStore host = do
    hPutStr stderr "."
    compressionsRef   <- newIORef allCompressions
    compressionIdsRef <- newIORef []
    loop compressionsRef compressionIdsRef
  where
    loop :: IORef [Compression] -> IORef [CompressionID] -> IO (HostName,[CompressionID])
    loop compressionsRef compressionIdsRef = do
        compressions <- readIORef compressionsRef
        if not (null compressions)
            then catch
                (do
                    result <- T.timeout (timeout*1000000) $
                        withContext host weakRng certStore allCiphersuites compressions $ \context -> do
                            contextHookSetHandshakeRecv context handshakeRecvHook
                            handshake context
                    case result of
                        Nothing -> return (host,[]) -- timed out
                        Just _  -> loop compressionsRef compressionIdsRef)
                (\(_ :: SomeException) -> makeReturnValue)
            else makeReturnValue
      where
        makeReturnValue :: IO (HostName,[CompressionID])
        makeReturnValue = (host,) <$> readIORef compressionIdsRef

        handshakeRecvHook :: Handshake -> IO Handshake
        handshakeRecvHook hs@(ServerHello _ _ _ _ cid _) = do
            modifyIORef' compressionsRef deleteSelectedCompression
            modifyIORef' compressionIdsRef (++ [cid])
            return hs
          where
            deleteSelectedCompression :: [Compression] -> [Compression]
            deleteSelectedCompression [] = []
            deleteSelectedCompression ((Compression x):xs)
                | compressionCID x == cid = xs
                | otherwise = Compression x : deleteSelectedCompression xs
        handshakeRecvHook hs = return hs
