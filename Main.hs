{-# LANGUAGE ScopedTypeVariables, TupleSections #-}

module Main where

import           Control.Applicative
import           Control.Exception
import           Control.Monad
import           Data.Default                        (def)
import           Data.IORef
import           Data.List                           (delete, isInfixOf, nub)
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
import Utils

data Metric
    = Ciphersuites
    | Compressions
    | Versions
    deriving Show

instance Read Metric where
    readPrec = lift (ciphersuites +++ compressions +++ versions)
      where
        ciphersuites, compressions, versions :: ReadP Metric
        ciphersuites = Ciphersuites <$ string "ciphersuites"
        compressions = Compressions <$ string "compressions"
        versions     = Versions     <$ string "versions"

data Cli = Cli
    { cliMetric     :: Metric
    , cliNumThreads :: Int
    , cliTimeout    :: Int
    , cliFrom       :: Maybe Int
    , cliTo         :: Maybe Int
    , cliHostfile   :: FilePath
    , cliDebug      :: Bool
    }

cli :: Parser Cli
cli = Cli <$> metric <*> numThreads <*> timeout <*> from <*> to <*> hostfile <*> debug
  where
    metric :: Parser Metric
    metric = option $
        short 'm' <>
        long "metric" <>
        help "\"ciphersuites\", \"compressions\", or \"versions\"" <>
        metavar "<string>"

    numThreads :: Parser Int
    numThreads = option $
        short 'n' <>
        long "num-threads" <>
        help "Thread pool size" <>
        value 10 <>
        metavar "<int>"

    timeout :: Parser Int
    timeout = option $
        short 't' <>
        long "timeout" <>
        help "The timeout (in seconds) before closing a connection" <>
        value 5 <>
        metavar "<int>"

    from :: Parser (Maybe Int)
    from = optional $ option $
        long "from" <>
        help "From host index" <>
        metavar "<int>"

    to :: Parser (Maybe Int)
    to = optional $ option $
        long "to" <>
        help "To host index" <>
        metavar "<int>"

    hostfile :: Parser String
    hostfile = argument str $
        help "The file of hosts to connect to, one per line" <>
        metavar "<filename>"

    debug :: Parser Bool
    debug = switch $
        short 'd' <>
        long "debug" <>
        help "Turn this flag on to log packets sent/recieved to stderr"

main :: IO ()
main = execParser opts >>= main2
  where
    opts = info (helper <*> cli) $
        fullDesc <>
        header (unlines [ "TLS Supported Capabilities Tool Thing Pro"
                        , "This is not free software! PLEASE PURCHASE"
                        ])

main2 :: Cli -> IO ()
main2 (Cli metric numThreads timeout mfrom mto hostfile debug) = do
    hSetBuffering stderr NoBuffering

    let from = maybe 0 id mfrom

    hosts     <- maybe id (\to -> take (to-from)) mto . drop from . lines <$> readFile hostfile
    certStore <- getSystemCertificateStore

    main3 metric certStore hosts
  where
    main3 :: Metric -> CertificateStore -> [HostName] -> IO ()
    main3 Ciphersuites = main4 getCiphersuites
    main3 Compressions = main4 getCompressions
    main3 Versions     = main4 getVersions

    main4 :: Show a
          => (Bool -> Int -> CertificateStore -> HostName -> IO (HostName,a))
          -> CertificateStore
          -> [HostName]
          -> IO ()
    main4 getMetric certStore hosts =
        parallelWithPoolOf numThreads (map (getMetric debug timeout certStore) hosts) >>= putStrLn . formatOutput
      where
        formatOutput :: Show a => [(HostName,a)] -> String
        formatOutput = unlines . map formatOutput'
          where
            formatOutput' :: Show a => (HostName,a) -> String
            formatOutput' (host, cs) = host ++ " " ++ show cs

getCiphersuites :: Bool -> Int -> CertificateStore -> HostName -> IO (HostName,[CipherID])
getCiphersuites debug timeout certStore host = do
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
                    let supported = def { supportedCiphers = ciphers }

                    result <- T.timeout (timeout*1000000) $
                        withContext host
                                    weakRng
                                    certStore
                                    supported $ \context -> do
                            contextHookSetHandshakeRecv context handshakeRecvHook
                            when debug $
                                contextHookSetLogging context def { loggingPacketSent = hPutStrLn stderr . ("SENT: " ++)
                                                                  , loggingPacketRecv = hPutStrLn stderr . ("RECV: " ++)
                                                                  }
                            handshake context
                    case result of
                        Nothing -> return (host,[]) -- timed out
                        Just _  -> loop ciphersRef cipherIdsRef)
                (\(_ :: SomeException) -> makeReturnValue) -- probably an alert, no ciphersuites accepted
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

getCompressions :: Bool -> Int -> CertificateStore -> HostName -> IO (HostName,[CompressionID])
getCompressions debug timeout certStore host = do
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
                    -- compression_methods<1..2^8-1> means at most 255 bytes
                    let supported = def { supportedCompressions = take 127 compressions
                                        , supportedCiphers = allCiphersuites
                                        }

                    result <- T.timeout (timeout*1000000) $
                        withContext host
                                    weakRng
                                    certStore
                                    supported
                            $ \context -> do
                                contextHookSetHandshakeRecv context handshakeRecvHook
                                when debug $
                                    contextHookSetLogging context def { loggingPacketSent = hPutStrLn stderr . ("SENT: " ++)
                                                                      , loggingPacketRecv = hPutStrLn stderr . ("RECV: " ++) }
                                handshake context
                    case result of
                        Nothing -> return (host,[]) -- timed out
                        Just _  -> loop compressionsRef compressionIdsRef)
                onError
            else makeReturnValue
      where
        onError :: SomeException -> IO (HostName,[CompressionID])
        onError e = case fromException e of
            -- A HandshakeFailed is expected because the (de)compression is not actually implemented, only the
            -- value is sent.
            Just (HandshakeFailed (Error_Packet_unexpected s _)) ->
                if "DecompressionFailure" `isInfixOf` s
                    then loop compressionsRef compressionIdsRef
                    else hPutStr stderr (show e) >> makeReturnValue
            -- hopefully this is a DecodeError, which we expect when the server didn't accept any compression methods
            Just _ -> makeReturnValue
            Nothing -> makeReturnValue

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


getVersions :: Bool -> Int -> CertificateStore -> HostName -> IO (HostName,[Version])
getVersions debug timeout certStore host = do
    hPutStr stderr "."
    versionsToTryRef    <- newIORef allVersions
    versionsAcceptedRef <- newIORef []
    loop versionsToTryRef versionsAcceptedRef
  where
    loop :: IORef [Version] -> IORef [Version] -> IO (HostName,[Version])
    loop versionsToTryRef versionsAcceptedRef = do
        versionsToTry <- readIORef versionsToTryRef
        if not (null versionsToTry)
            then catch
                (do
                    let supported = def { supportedVersions = versionsToTry
                                        , supportedCiphers = allCiphersuites
                                        }

                    result <- T.timeout (timeout*1000000) $
                        withContext host
                                    weakRng
                                    certStore
                                    supported
                            $ \context -> do
                                contextHookSetHandshakeRecv context handshakeRecvHook
                                when debug $
                                    contextHookSetLogging context def { loggingPacketSent = hPutStrLn stderr . ("SENT: " ++)
                                                                      , loggingPacketRecv = hPutStrLn stderr . ("RECV: " ++)
                                                                      }
                                handshake context
                    case result of
                        Nothing -> return (host,[])  -- timed out
                        Just _  -> loop versionsToTryRef versionsAcceptedRef)
                (\(_ :: SomeException) -> makeReturnValue) -- probably an alert, no version accepted
            else makeReturnValue
      where
        -- nub, because a ChangeCipherSpec message is required when a server responds with a different
        -- version than the one requested, resulting in possibly logging the same version recieved
        makeReturnValue :: IO (HostName,[Version])
        makeReturnValue = (host,) . nub <$> readIORef versionsAcceptedRef

        handshakeRecvHook :: Handshake -> IO Handshake
        handshakeRecvHook hs@(ServerHello ver _ _ _ _ _) = do
            modifyIORef' versionsToTryRef (delete ver)
            modifyIORef' versionsAcceptedRef (++ [ver])
            return hs
        handshakeRecvHook hs = return hs
