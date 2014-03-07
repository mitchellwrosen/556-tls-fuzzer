{-# LANGUAGE LambdaCase, ScopedTypeVariables #-}

module Main where

import Data.Default (def)
import Network.TLS
import Network.TLS.IO
import Network.TLS.Struct
import System.IO
import System.X509                (getSystemCertificateStore)

import           Control.Applicative
import           Control.Exception
import           Control.Monad
import           Data.X509.CertificateStore          (CertificateStore)
import           Network.Simple.TCP
import           Options.Applicative
import qualified System.Timeout                      as T

import Tls
import Utils

data ServerResponse
    = Correct
    | Incorrect
    | Ex TLSException
    | None
    deriving Show

data Cli = Cli
    { cliNumThreads :: Int
    , cliTimeout    :: Int
    , cliFrom       :: Maybe Int
    , cliTo         :: Maybe Int
    , cliHostfile   :: FilePath
    , cliDebug      :: Bool
    }

cli :: Parser Cli
cli = Cli <$> numThreads <*> timeout <*> from <*> to <*> hostfile <*> debug
  where
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
main2 (Cli numThreads timeout mfrom mto hostfile debug) = do
    hSetBuffering stderr NoBuffering

    let from = maybe 0 id mfrom

    hosts     <- maybe id (\to -> take (to-from)) mto . drop from . lines <$> readFile hostfile
    certStore <- getSystemCertificateStore

    main3 certStore hosts
  where
    main3 :: CertificateStore -> [HostName] -> IO ()
    main3 certStore hosts =
        parallelWithPoolOf numThreads (map (fuzz1 debug timeout certStore) hosts) >>= putStrLn . formatOutput
      where
        formatOutput :: Show a => [(HostName,a)] -> String
        formatOutput = unlines . map formatOutput'
          where
            formatOutput' :: Show a => (HostName,a) -> String
            formatOutput' (host, cs) = host ++ " " ++ show cs

fuzz1 :: Bool -> Int -> CertificateStore -> HostName -> IO (HostName, ServerResponse)
fuzz1 debug timeout certStore host = do
    hPutStr stderr "."
    catch fuzz1' onError
  where
    onError :: SomeException -> IO (HostName, ServerResponse)
    onError e = case fromException e :: Maybe TLSException of
        -- We only expect a TLSException...
        Nothing -> return (host, None)
        -- In fact, only a specific TLSException
        Just (Terminated _ _ (Error_Protocol (_, _, UnexpectedMessage))) -> return (host, Correct)
        Just err -> return (host, Ex err)

    fuzz1' :: IO (HostName, ServerResponse)
    fuzz1' = do
        gotResponse <- T.timeout (timeout*1000000) $
            withContext host weakRng certStore supported $ \context -> do
                when debug $
                    contextHookSetLogging context logging
                handshake context
                sendPacket context Dummy
                void $ T.timeout (timeout*1000000) $ recvData context -- expect TLSException thrown here
        case gotResponse of
            Nothing -> return (host, None) -- timed out, no response
            Just _ -> return (host, Incorrect) -- any response that doesn't throw a TLSException is incorrect

supported :: Supported
supported = def { supportedCiphers = allCiphersuites }

logging :: Logging
logging = def
    { loggingPacketSent = hPutStrLn stderr . ("SENT: " ++)
    , loggingPacketRecv = hPutStrLn stderr . ("RECV: " ++)
    }
