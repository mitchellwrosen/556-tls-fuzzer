module Main where

import Control.Applicative
import Control.Exception
import Crypto.Random
import Data.Default (def)
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
        [host] -> main' host
        _ -> hPutStrLn stderr "Usage: ./a.out host"

main' :: String -> IO ()
main' host = do
    certStore <- getSystemCertificateStore

    withContext host weakRng certStore allCiphersuites $ \context -> do
        contextHookSetLogging context (def { loggingPacketSent = putStrLn
                                           , loggingPacketRecv = putStrLn
                                           })
        handshake context
