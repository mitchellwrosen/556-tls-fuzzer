{-# LANGUAGE OverloadedStrings #-}

module Tls
    ( allCiphersuites
    , weakRng
    , withContext
    ) where

import Control.Exception
import Crypto.Random
import Data.Default
import Data.X509.CertificateStore (CertificateStore)
import Network.Simple.TCP
import Network.TLS
import Network.TLS.Extra.Cipher

import qualified Data.ByteString as BS

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

weakRng :: SystemRNG
weakRng = cprgCreate (createTestEntropyPool "foobar")

withContext :: CPRG a
            => HostName
            -> a
            -> CertificateStore
            -> [Cipher]
            -> (Context -> IO b)
            -> IO b
withContext host rng certStore ciphers = bracket (makeContext host rng certStore ciphers) contextClose

withTcpSocket :: HostName -> ServiceName -> ((Socket, SockAddr) -> IO a) -> IO a
withTcpSocket host port = bracketOnError (connectSock host port) (closeSock . fst)

makeContext :: CPRG a
            => HostName
            -> a
            -> CertificateStore
            -> [Cipher]
            -> IO Context
makeContext host rng certStore ciphers = withTcpSocket host "443" $ \(sock, _) -> do
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
