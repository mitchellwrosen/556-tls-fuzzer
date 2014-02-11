{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}

module Main where

import Control.Applicative
import Control.Exception
import Control.Monad
import Crypto.Random
import Crypto.Random.API
{-import Crypto.Random.AESCtr (AESRNG, makeSystem)-}
import Data.Default
import Data.IORef
import Data.X509.CertificateStore (CertificateStore)
import Network.Simple.TCP
import Network.TLS
import Network.TLS.Extra.Cipher
import Network.TLS.Struct
import System.Environment (getArgs)
import System.IO
import System.X509 (getSystemCertificateStore)

import qualified Data.ByteString as BS

import Debug.Trace

tracem :: Monad m => String -> m ()
tracem = flip trace (return ())

allCiphersuites :: [Cipher]
allCiphersuites =
    [ cipher_DHE_RSA_AES256_SHA256
    , cipher_DHE_RSA_AES128_SHA256
    , cipher_DHE_RSA_AES256_SHA1
    , cipher_DHE_RSA_AES128_SHA1
    , cipher_DHE_DSS_AES256_SHA1
    , cipher_DHE_DSS_AES128_SHA1
    , cipher_AES128_SHA256
    , cipher_AES256_SHA256
    , cipher_AES128_SHA1
    , cipher_AES256_SHA1
    , cipher_DHE_DSS_RC4_SHA1
    , cipher_RC4_128_SHA1
    , cipher_RC4_128_MD5
    , cipher_null_SHA1
    , cipher_null_MD5
    ]

main :: IO ()
main = do
    [hostfile] <- getArgs
    hosts <- lines <$> readFile hostfile
    out_h <- openFile "results.out" WriteMode

    let rng = cprgCreate (createTestEntropyPool "foobar") :: SystemRNG -- no need for secure RNG
    certStore <- getSystemCertificateStore

    forM_ hosts $ \host -> do
        ciphersRef <- newIORef allCiphersuites
        hPutStr out_h host
        loop1 out_h rng certStore ciphersRef host

    hClose out_h
      where
        loop1 :: CPRG a => Handle -> a -> CertificateStore -> IORef [Cipher] -> HostName -> IO ()
        loop1 out_h rng certStore ciphersRef host = do
            ciphers <- readIORef ciphersRef
            if not (null ciphers)
                then loop2 ciphers `catch` (\(_ :: SomeException) -> hPutStrLn out_h "")
                else hPutStrLn out_h ""
          where
            loop2 :: [Cipher] -> IO ()
            loop2 ciphers = do
                withContext (makeContext host
                                         "443"
                                         rng
                                         certStore
                                         ciphers) $ \context -> do
                    contextHookSetHandshakeRecv context (handshakeRecvHook ciphersRef out_h)

                    {-contextHookSetLogging context (def { loggingPacketSent = putStrLn-}
                                                       {-, loggingPacketRecv = putStrLn-}
                                                       {-})-}
                    handshake context
                loop1 out_h rng certStore ciphersRef host

handshakeRecvHook :: IORef [Cipher] -> Handle -> Handshake -> IO Handshake
handshakeRecvHook ciphers out_h hs@(ServerHello _ _ _ cid _ _) = do
    putStrLn $ "Server accepted " ++ show cid
    hPutStr out_h $ ' ' : show cid
    -- Remove all ciphers up to and including the accepted cipher
    modifyIORef ciphers (drop 1 . dropWhile (\c -> cipherID c /= cid))
    return hs
handshakeRecvHook _ _ hs = return hs

withContext :: IO Context -> (Context -> IO a) -> IO a
withContext getContext action = do
    context <- getContext
    ret <- action context
    contextClose context
    return ret

withTcpSocket :: HostName -> ServiceName -> ((Socket, SockAddr) -> IO a) -> IO a
withTcpSocket host port = bracketOnError (connectSock host port) (closeSock . fst)

makeContext :: CPRG a
            => HostName
            -> ServiceName
            -> a
            -> CertificateStore
            -> [Cipher]
            -> IO Context
makeContext host port rng certStore ciphers = withTcpSocket host port $ \(sock, _) -> do
    let params = ClientParams {
          clientUseMaxFragmentLength    = Nothing
        , clientServerIdentification    = (host, BS.empty)
        , clientUseServerNameIndication = True -- TODO ?
        , clientWantSessionResume       = Nothing
        , clientShared                  = def { sharedCAStore = certStore }
        , clientHooks                   = def
        , clientSupported               = def { supportedCiphers = ciphers }
        }

    contextNew sock params rng
