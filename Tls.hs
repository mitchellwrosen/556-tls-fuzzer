{-# LANGUAGE OverloadedStrings #-}

module Tls
    ( allCiphersuites
    , weakRng
    , withContext
    ) where

import           Control.Exception          (bracket, bracketOnError)
import           Crypto.Random              (CPRG, SystemRNG, cprgCreate, createTestEntropyPool)
import qualified Data.ByteString            as BS
import           Data.Default               (def)
import           Data.X509.CertificateStore (CertificateStore)
import           Network.Simple.TCP         (HostName, ServiceName, SockAddr, Socket, closeSock, connectSock)
import           Network.TLS                (Cipher, ClientParams(..), Context, Shared(..), Supported(..), contextClose, contextNew)
import           Network.TLS.Extra.Cipher

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
withContext host rng certStore ciphers =
    bracket
        (makeContext host rng certStore ciphers)
        contextClose

-- | Like Network.Simple.TCP.connect, but keep the socket alive after the
-- provided action.
withPersistentTcp :: HostName -> ServiceName -> ((Socket, SockAddr) -> IO a) -> IO a
withPersistentTcp host port = bracketOnError (connectSock host port) (closeSock . fst)

makeContext :: CPRG a
            => HostName
            -> a
            -> CertificateStore
            -> [Cipher]
            -> IO Context
makeContext host rng certStore ciphers = do
    withPersistentTcp host "443" $ \(sock, _) -> do
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
