{-# LANGUAGE OverloadedStrings #-}

module Tls where
    {-( allCiphersuites-}
    {-, allCompressions-}
    {-, weakRng-}
    {-, withContext-}
    {-) where-}

import           Control.Exception          (bracket, bracketOnError)
import           Crypto.Random              (CPRG, SystemRNG, cprgCreate, createTestEntropyPool)
import qualified Data.ByteString            as BS
import           Data.Default               (def)
import           Data.X509.CertificateStore (CertificateStore)
import           Network.Simple.TCP         (HostName, ServiceName, SockAddr, Socket, closeSock, connectSock)
import           Network.TLS                -- (Cipher, ClientParams(..), Context, Shared(..), Supported(..), contextClose, contextNew)
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

allCompressions :: [Compression]
allCompressions =
    [ nullCompression
    , Compression Compression1
    , Compression Compression2
    , Compression Compression3
    , Compression Compression4
    , Compression Compression5
    , Compression Compression6
    , Compression Compression7
    , Compression Compression8
    , Compression Compression9
    , Compression Compression10
    , Compression Compression11
    , Compression Compression12
    , Compression Compression13
    , Compression Compression14
    , Compression Compression15
    , Compression Compression16
    , Compression Compression17
    , Compression Compression18
    , Compression Compression19
    , Compression Compression20
    , Compression Compression21
    , Compression Compression22
    , Compression Compression23
    , Compression Compression24
    , Compression Compression25
    , Compression Compression26
    , Compression Compression27
    , Compression Compression28
    , Compression Compression29
    , Compression Compression30
    , Compression Compression31
    , Compression Compression32
    , Compression Compression33
    , Compression Compression34
    , Compression Compression35
    , Compression Compression36
    , Compression Compression37
    , Compression Compression38
    , Compression Compression39
    , Compression Compression40
    , Compression Compression41
    , Compression Compression42
    , Compression Compression43
    , Compression Compression44
    , Compression Compression45
    , Compression Compression46
    , Compression Compression47
    , Compression Compression48
    , Compression Compression49
    , Compression Compression50
    , Compression Compression51
    , Compression Compression52
    , Compression Compression53
    , Compression Compression54
    , Compression Compression55
    , Compression Compression56
    , Compression Compression57
    , Compression Compression58
    , Compression Compression59
    , Compression Compression60
    , Compression Compression61
    , Compression Compression62
    , Compression Compression63
    , Compression Compression64
    , Compression Compression65
    , Compression Compression66
    , Compression Compression67
    , Compression Compression68
    , Compression Compression69
    , Compression Compression70
    , Compression Compression71
    , Compression Compression72
    , Compression Compression73
    , Compression Compression74
    , Compression Compression75
    , Compression Compression76
    , Compression Compression77
    , Compression Compression78
    , Compression Compression79
    , Compression Compression80
    , Compression Compression81
    , Compression Compression82
    , Compression Compression83
    , Compression Compression84
    , Compression Compression85
    , Compression Compression86
    , Compression Compression87
    , Compression Compression88
    , Compression Compression89
    , Compression Compression90
    , Compression Compression91
    , Compression Compression92
    , Compression Compression93
    , Compression Compression94
    , Compression Compression95
    , Compression Compression96
    , Compression Compression97
    , Compression Compression98
    , Compression Compression99
    , Compression Compression100
    , Compression Compression101
    , Compression Compression102
    , Compression Compression103
    , Compression Compression104
    , Compression Compression105
    , Compression Compression106
    , Compression Compression107
    , Compression Compression108
    , Compression Compression109
    , Compression Compression110
    , Compression Compression111
    , Compression Compression112
    , Compression Compression113
    , Compression Compression114
    , Compression Compression115
    , Compression Compression116
    , Compression Compression117
    , Compression Compression118
    , Compression Compression119
    , Compression Compression120
    , Compression Compression121
    , Compression Compression122
    , Compression Compression123
    , Compression Compression124
    , Compression Compression125
    , Compression Compression126
    , Compression Compression127
    , Compression Compression128
    , Compression Compression129
    , Compression Compression130
    , Compression Compression131
    , Compression Compression132
    , Compression Compression133
    , Compression Compression134
    , Compression Compression135
    , Compression Compression136
    , Compression Compression137
    , Compression Compression138
    , Compression Compression139
    , Compression Compression140
    , Compression Compression141
    , Compression Compression142
    , Compression Compression143
    , Compression Compression144
    , Compression Compression145
    , Compression Compression146
    , Compression Compression147
    , Compression Compression148
    , Compression Compression149
    , Compression Compression150
    , Compression Compression151
    , Compression Compression152
    , Compression Compression153
    , Compression Compression154
    , Compression Compression155
    , Compression Compression156
    , Compression Compression157
    , Compression Compression158
    , Compression Compression159
    , Compression Compression160
    , Compression Compression161
    , Compression Compression162
    , Compression Compression163
    , Compression Compression164
    , Compression Compression165
    , Compression Compression166
    , Compression Compression167
    , Compression Compression168
    , Compression Compression169
    , Compression Compression170
    , Compression Compression171
    , Compression Compression172
    , Compression Compression173
    , Compression Compression174
    , Compression Compression175
    , Compression Compression176
    , Compression Compression177
    , Compression Compression178
    , Compression Compression179
    , Compression Compression180
    , Compression Compression181
    , Compression Compression182
    , Compression Compression183
    , Compression Compression184
    , Compression Compression185
    , Compression Compression186
    , Compression Compression187
    , Compression Compression188
    , Compression Compression189
    , Compression Compression190
    , Compression Compression191
    , Compression Compression192
    , Compression Compression193
    , Compression Compression194
    , Compression Compression195
    , Compression Compression196
    , Compression Compression197
    , Compression Compression198
    , Compression Compression199
    , Compression Compression200
    , Compression Compression201
    , Compression Compression202
    , Compression Compression203
    , Compression Compression204
    , Compression Compression205
    , Compression Compression206
    , Compression Compression207
    , Compression Compression208
    , Compression Compression209
    , Compression Compression210
    , Compression Compression211
    , Compression Compression212
    , Compression Compression213
    , Compression Compression214
    , Compression Compression215
    , Compression Compression216
    , Compression Compression217
    , Compression Compression218
    , Compression Compression219
    , Compression Compression220
    , Compression Compression221
    , Compression Compression222
    , Compression Compression223
    , Compression Compression224
    , Compression Compression225
    , Compression Compression226
    , Compression Compression227
    , Compression Compression228
    , Compression Compression229
    , Compression Compression230
    , Compression Compression231
    , Compression Compression232
    , Compression Compression233
    , Compression Compression234
    , Compression Compression235
    , Compression Compression236
    , Compression Compression237
    , Compression Compression238
    , Compression Compression239
    , Compression Compression240
    , Compression Compression241
    , Compression Compression242
    , Compression Compression243
    , Compression Compression244
    , Compression Compression245
    , Compression Compression246
    , Compression Compression247
    , Compression Compression248
    , Compression Compression249
    , Compression Compression250
    , Compression Compression251
    , Compression Compression252
    , Compression Compression253
    , Compression Compression254
    , Compression Compression255
    ]

weakRng :: SystemRNG
weakRng = cprgCreate (createTestEntropyPool "foobar")

withContext :: CPRG a
            => HostName
            -> a
            -> CertificateStore
            -> [Cipher]
            -> [Compression]
            -> (Context -> IO b)
            -> IO b
withContext host rng certStore ciphers compressions =
    bracket
        (makeContext host rng certStore ciphers compressions)
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
            -> [Compression]
            -> IO Context
makeContext host rng certStore ciphers compressions = do
    withPersistentTcp host "443" $ \(sock, _) -> do
        let params = ClientParams {
              clientUseMaxFragmentLength    = Nothing
            , clientServerIdentification    = (host, BS.empty)
            , clientUseServerNameIndication = True -- TODO ?
            , clientWantSessionResume       = Nothing
            , clientShared                  = def { sharedCAStore = certStore }
            , clientHooks                   = def
            , clientSupported               = def { supportedCiphers = ciphers
                                                  , supportedCompressions = compressions
                                                  }
            }

        contextNew sock params rng

data Compression1 = Compression1
instance CompressionC Compression1 where
    compressionCID _ = 1
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression2 = Compression2
instance CompressionC Compression2 where
    compressionCID _ = 2
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression3 = Compression3
instance CompressionC Compression3 where
    compressionCID _ = 3
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression4 = Compression4
instance CompressionC Compression4 where
    compressionCID _ = 4
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression5 = Compression5
instance CompressionC Compression5 where
    compressionCID _ = 5
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression6 = Compression6
instance CompressionC Compression6 where
    compressionCID _ = 6
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression7 = Compression7
instance CompressionC Compression7 where
    compressionCID _ = 7
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression8 = Compression8
instance CompressionC Compression8 where
    compressionCID _ = 8
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression9 = Compression9
instance CompressionC Compression9 where
    compressionCID _ = 9
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression10 = Compression10
instance CompressionC Compression10 where
    compressionCID _ = 10
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression11 = Compression11
instance CompressionC Compression11 where
    compressionCID _ = 11
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression12 = Compression12
instance CompressionC Compression12 where
    compressionCID _ = 12
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression13 = Compression13
instance CompressionC Compression13 where
    compressionCID _ = 13
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression14 = Compression14
instance CompressionC Compression14 where
    compressionCID _ = 14
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression15 = Compression15
instance CompressionC Compression15 where
    compressionCID _ = 15
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression16 = Compression16
instance CompressionC Compression16 where
    compressionCID _ = 16
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression17 = Compression17
instance CompressionC Compression17 where
    compressionCID _ = 17
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression18 = Compression18
instance CompressionC Compression18 where
    compressionCID _ = 18
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression19 = Compression19
instance CompressionC Compression19 where
    compressionCID _ = 19
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression20 = Compression20
instance CompressionC Compression20 where
    compressionCID _ = 20
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression21 = Compression21
instance CompressionC Compression21 where
    compressionCID _ = 21
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression22 = Compression22
instance CompressionC Compression22 where
    compressionCID _ = 22
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression23 = Compression23
instance CompressionC Compression23 where
    compressionCID _ = 23
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression24 = Compression24
instance CompressionC Compression24 where
    compressionCID _ = 24
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression25 = Compression25
instance CompressionC Compression25 where
    compressionCID _ = 25
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression26 = Compression26
instance CompressionC Compression26 where
    compressionCID _ = 26
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression27 = Compression27
instance CompressionC Compression27 where
    compressionCID _ = 27
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression28 = Compression28
instance CompressionC Compression28 where
    compressionCID _ = 28
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression29 = Compression29
instance CompressionC Compression29 where
    compressionCID _ = 29
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression30 = Compression30
instance CompressionC Compression30 where
    compressionCID _ = 30
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression31 = Compression31
instance CompressionC Compression31 where
    compressionCID _ = 31
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression32 = Compression32
instance CompressionC Compression32 where
    compressionCID _ = 32
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression33 = Compression33
instance CompressionC Compression33 where
    compressionCID _ = 33
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression34 = Compression34
instance CompressionC Compression34 where
    compressionCID _ = 34
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression35 = Compression35
instance CompressionC Compression35 where
    compressionCID _ = 35
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression36 = Compression36
instance CompressionC Compression36 where
    compressionCID _ = 36
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression37 = Compression37
instance CompressionC Compression37 where
    compressionCID _ = 37
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression38 = Compression38
instance CompressionC Compression38 where
    compressionCID _ = 38
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression39 = Compression39
instance CompressionC Compression39 where
    compressionCID _ = 39
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression40 = Compression40
instance CompressionC Compression40 where
    compressionCID _ = 40
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression41 = Compression41
instance CompressionC Compression41 where
    compressionCID _ = 41
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression42 = Compression42
instance CompressionC Compression42 where
    compressionCID _ = 42
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression43 = Compression43
instance CompressionC Compression43 where
    compressionCID _ = 43
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression44 = Compression44
instance CompressionC Compression44 where
    compressionCID _ = 44
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression45 = Compression45
instance CompressionC Compression45 where
    compressionCID _ = 45
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression46 = Compression46
instance CompressionC Compression46 where
    compressionCID _ = 46
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression47 = Compression47
instance CompressionC Compression47 where
    compressionCID _ = 47
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression48 = Compression48
instance CompressionC Compression48 where
    compressionCID _ = 48
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression49 = Compression49
instance CompressionC Compression49 where
    compressionCID _ = 49
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression50 = Compression50
instance CompressionC Compression50 where
    compressionCID _ = 50
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression51 = Compression51
instance CompressionC Compression51 where
    compressionCID _ = 51
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression52 = Compression52
instance CompressionC Compression52 where
    compressionCID _ = 52
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression53 = Compression53
instance CompressionC Compression53 where
    compressionCID _ = 53
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression54 = Compression54
instance CompressionC Compression54 where
    compressionCID _ = 54
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression55 = Compression55
instance CompressionC Compression55 where
    compressionCID _ = 55
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression56 = Compression56
instance CompressionC Compression56 where
    compressionCID _ = 56
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression57 = Compression57
instance CompressionC Compression57 where
    compressionCID _ = 57
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression58 = Compression58
instance CompressionC Compression58 where
    compressionCID _ = 58
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression59 = Compression59
instance CompressionC Compression59 where
    compressionCID _ = 59
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression60 = Compression60
instance CompressionC Compression60 where
    compressionCID _ = 60
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression61 = Compression61
instance CompressionC Compression61 where
    compressionCID _ = 61
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression62 = Compression62
instance CompressionC Compression62 where
    compressionCID _ = 62
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression63 = Compression63
instance CompressionC Compression63 where
    compressionCID _ = 63
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression64 = Compression64
instance CompressionC Compression64 where
    compressionCID _ = 64
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression65 = Compression65
instance CompressionC Compression65 where
    compressionCID _ = 65
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression66 = Compression66
instance CompressionC Compression66 where
    compressionCID _ = 66
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression67 = Compression67
instance CompressionC Compression67 where
    compressionCID _ = 67
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression68 = Compression68
instance CompressionC Compression68 where
    compressionCID _ = 68
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression69 = Compression69
instance CompressionC Compression69 where
    compressionCID _ = 69
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression70 = Compression70
instance CompressionC Compression70 where
    compressionCID _ = 70
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression71 = Compression71
instance CompressionC Compression71 where
    compressionCID _ = 71
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression72 = Compression72
instance CompressionC Compression72 where
    compressionCID _ = 72
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression73 = Compression73
instance CompressionC Compression73 where
    compressionCID _ = 73
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression74 = Compression74
instance CompressionC Compression74 where
    compressionCID _ = 74
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression75 = Compression75
instance CompressionC Compression75 where
    compressionCID _ = 75
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression76 = Compression76
instance CompressionC Compression76 where
    compressionCID _ = 76
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression77 = Compression77
instance CompressionC Compression77 where
    compressionCID _ = 77
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression78 = Compression78
instance CompressionC Compression78 where
    compressionCID _ = 78
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression79 = Compression79
instance CompressionC Compression79 where
    compressionCID _ = 79
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression80 = Compression80
instance CompressionC Compression80 where
    compressionCID _ = 80
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression81 = Compression81
instance CompressionC Compression81 where
    compressionCID _ = 81
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression82 = Compression82
instance CompressionC Compression82 where
    compressionCID _ = 82
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression83 = Compression83
instance CompressionC Compression83 where
    compressionCID _ = 83
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression84 = Compression84
instance CompressionC Compression84 where
    compressionCID _ = 84
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression85 = Compression85
instance CompressionC Compression85 where
    compressionCID _ = 85
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression86 = Compression86
instance CompressionC Compression86 where
    compressionCID _ = 86
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression87 = Compression87
instance CompressionC Compression87 where
    compressionCID _ = 87
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression88 = Compression88
instance CompressionC Compression88 where
    compressionCID _ = 88
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression89 = Compression89
instance CompressionC Compression89 where
    compressionCID _ = 89
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression90 = Compression90
instance CompressionC Compression90 where
    compressionCID _ = 90
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression91 = Compression91
instance CompressionC Compression91 where
    compressionCID _ = 91
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression92 = Compression92
instance CompressionC Compression92 where
    compressionCID _ = 92
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression93 = Compression93
instance CompressionC Compression93 where
    compressionCID _ = 93
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression94 = Compression94
instance CompressionC Compression94 where
    compressionCID _ = 94
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression95 = Compression95
instance CompressionC Compression95 where
    compressionCID _ = 95
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression96 = Compression96
instance CompressionC Compression96 where
    compressionCID _ = 96
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression97 = Compression97
instance CompressionC Compression97 where
    compressionCID _ = 97
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression98 = Compression98
instance CompressionC Compression98 where
    compressionCID _ = 98
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression99 = Compression99
instance CompressionC Compression99 where
    compressionCID _ = 99
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression100 = Compression100
instance CompressionC Compression100 where
    compressionCID _ = 100
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression101 = Compression101
instance CompressionC Compression101 where
    compressionCID _ = 101
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression102 = Compression102
instance CompressionC Compression102 where
    compressionCID _ = 102
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression103 = Compression103
instance CompressionC Compression103 where
    compressionCID _ = 103
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression104 = Compression104
instance CompressionC Compression104 where
    compressionCID _ = 104
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression105 = Compression105
instance CompressionC Compression105 where
    compressionCID _ = 105
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression106 = Compression106
instance CompressionC Compression106 where
    compressionCID _ = 106
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression107 = Compression107
instance CompressionC Compression107 where
    compressionCID _ = 107
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression108 = Compression108
instance CompressionC Compression108 where
    compressionCID _ = 108
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression109 = Compression109
instance CompressionC Compression109 where
    compressionCID _ = 109
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression110 = Compression110
instance CompressionC Compression110 where
    compressionCID _ = 110
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression111 = Compression111
instance CompressionC Compression111 where
    compressionCID _ = 111
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression112 = Compression112
instance CompressionC Compression112 where
    compressionCID _ = 112
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression113 = Compression113
instance CompressionC Compression113 where
    compressionCID _ = 113
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression114 = Compression114
instance CompressionC Compression114 where
    compressionCID _ = 114
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression115 = Compression115
instance CompressionC Compression115 where
    compressionCID _ = 115
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression116 = Compression116
instance CompressionC Compression116 where
    compressionCID _ = 116
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression117 = Compression117
instance CompressionC Compression117 where
    compressionCID _ = 117
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression118 = Compression118
instance CompressionC Compression118 where
    compressionCID _ = 118
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression119 = Compression119
instance CompressionC Compression119 where
    compressionCID _ = 119
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression120 = Compression120
instance CompressionC Compression120 where
    compressionCID _ = 120
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression121 = Compression121
instance CompressionC Compression121 where
    compressionCID _ = 121
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression122 = Compression122
instance CompressionC Compression122 where
    compressionCID _ = 122
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression123 = Compression123
instance CompressionC Compression123 where
    compressionCID _ = 123
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression124 = Compression124
instance CompressionC Compression124 where
    compressionCID _ = 124
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression125 = Compression125
instance CompressionC Compression125 where
    compressionCID _ = 125
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression126 = Compression126
instance CompressionC Compression126 where
    compressionCID _ = 126
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression127 = Compression127
instance CompressionC Compression127 where
    compressionCID _ = 127
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression128 = Compression128
instance CompressionC Compression128 where
    compressionCID _ = 128
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression129 = Compression129
instance CompressionC Compression129 where
    compressionCID _ = 129
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression130 = Compression130
instance CompressionC Compression130 where
    compressionCID _ = 130
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression131 = Compression131
instance CompressionC Compression131 where
    compressionCID _ = 131
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression132 = Compression132
instance CompressionC Compression132 where
    compressionCID _ = 132
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression133 = Compression133
instance CompressionC Compression133 where
    compressionCID _ = 133
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression134 = Compression134
instance CompressionC Compression134 where
    compressionCID _ = 134
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression135 = Compression135
instance CompressionC Compression135 where
    compressionCID _ = 135
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression136 = Compression136
instance CompressionC Compression136 where
    compressionCID _ = 136
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression137 = Compression137
instance CompressionC Compression137 where
    compressionCID _ = 137
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression138 = Compression138
instance CompressionC Compression138 where
    compressionCID _ = 138
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression139 = Compression139
instance CompressionC Compression139 where
    compressionCID _ = 139
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression140 = Compression140
instance CompressionC Compression140 where
    compressionCID _ = 140
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression141 = Compression141
instance CompressionC Compression141 where
    compressionCID _ = 141
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression142 = Compression142
instance CompressionC Compression142 where
    compressionCID _ = 142
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression143 = Compression143
instance CompressionC Compression143 where
    compressionCID _ = 143
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression144 = Compression144
instance CompressionC Compression144 where
    compressionCID _ = 144
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression145 = Compression145
instance CompressionC Compression145 where
    compressionCID _ = 145
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression146 = Compression146
instance CompressionC Compression146 where
    compressionCID _ = 146
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression147 = Compression147
instance CompressionC Compression147 where
    compressionCID _ = 147
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression148 = Compression148
instance CompressionC Compression148 where
    compressionCID _ = 148
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression149 = Compression149
instance CompressionC Compression149 where
    compressionCID _ = 149
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression150 = Compression150
instance CompressionC Compression150 where
    compressionCID _ = 150
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression151 = Compression151
instance CompressionC Compression151 where
    compressionCID _ = 151
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression152 = Compression152
instance CompressionC Compression152 where
    compressionCID _ = 152
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression153 = Compression153
instance CompressionC Compression153 where
    compressionCID _ = 153
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression154 = Compression154
instance CompressionC Compression154 where
    compressionCID _ = 154
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression155 = Compression155
instance CompressionC Compression155 where
    compressionCID _ = 155
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression156 = Compression156
instance CompressionC Compression156 where
    compressionCID _ = 156
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression157 = Compression157
instance CompressionC Compression157 where
    compressionCID _ = 157
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression158 = Compression158
instance CompressionC Compression158 where
    compressionCID _ = 158
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression159 = Compression159
instance CompressionC Compression159 where
    compressionCID _ = 159
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression160 = Compression160
instance CompressionC Compression160 where
    compressionCID _ = 160
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression161 = Compression161
instance CompressionC Compression161 where
    compressionCID _ = 161
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression162 = Compression162
instance CompressionC Compression162 where
    compressionCID _ = 162
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression163 = Compression163
instance CompressionC Compression163 where
    compressionCID _ = 163
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression164 = Compression164
instance CompressionC Compression164 where
    compressionCID _ = 164
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression165 = Compression165
instance CompressionC Compression165 where
    compressionCID _ = 165
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression166 = Compression166
instance CompressionC Compression166 where
    compressionCID _ = 166
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression167 = Compression167
instance CompressionC Compression167 where
    compressionCID _ = 167
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression168 = Compression168
instance CompressionC Compression168 where
    compressionCID _ = 168
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression169 = Compression169
instance CompressionC Compression169 where
    compressionCID _ = 169
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression170 = Compression170
instance CompressionC Compression170 where
    compressionCID _ = 170
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression171 = Compression171
instance CompressionC Compression171 where
    compressionCID _ = 171
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression172 = Compression172
instance CompressionC Compression172 where
    compressionCID _ = 172
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression173 = Compression173
instance CompressionC Compression173 where
    compressionCID _ = 173
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression174 = Compression174
instance CompressionC Compression174 where
    compressionCID _ = 174
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression175 = Compression175
instance CompressionC Compression175 where
    compressionCID _ = 175
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression176 = Compression176
instance CompressionC Compression176 where
    compressionCID _ = 176
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression177 = Compression177
instance CompressionC Compression177 where
    compressionCID _ = 177
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression178 = Compression178
instance CompressionC Compression178 where
    compressionCID _ = 178
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression179 = Compression179
instance CompressionC Compression179 where
    compressionCID _ = 179
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression180 = Compression180
instance CompressionC Compression180 where
    compressionCID _ = 180
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression181 = Compression181
instance CompressionC Compression181 where
    compressionCID _ = 181
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression182 = Compression182
instance CompressionC Compression182 where
    compressionCID _ = 182
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression183 = Compression183
instance CompressionC Compression183 where
    compressionCID _ = 183
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression184 = Compression184
instance CompressionC Compression184 where
    compressionCID _ = 184
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression185 = Compression185
instance CompressionC Compression185 where
    compressionCID _ = 185
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression186 = Compression186
instance CompressionC Compression186 where
    compressionCID _ = 186
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression187 = Compression187
instance CompressionC Compression187 where
    compressionCID _ = 187
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression188 = Compression188
instance CompressionC Compression188 where
    compressionCID _ = 188
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression189 = Compression189
instance CompressionC Compression189 where
    compressionCID _ = 189
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression190 = Compression190
instance CompressionC Compression190 where
    compressionCID _ = 190
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression191 = Compression191
instance CompressionC Compression191 where
    compressionCID _ = 191
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression192 = Compression192
instance CompressionC Compression192 where
    compressionCID _ = 192
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression193 = Compression193
instance CompressionC Compression193 where
    compressionCID _ = 193
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression194 = Compression194
instance CompressionC Compression194 where
    compressionCID _ = 194
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression195 = Compression195
instance CompressionC Compression195 where
    compressionCID _ = 195
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression196 = Compression196
instance CompressionC Compression196 where
    compressionCID _ = 196
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression197 = Compression197
instance CompressionC Compression197 where
    compressionCID _ = 197
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression198 = Compression198
instance CompressionC Compression198 where
    compressionCID _ = 198
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression199 = Compression199
instance CompressionC Compression199 where
    compressionCID _ = 199
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression200 = Compression200
instance CompressionC Compression200 where
    compressionCID _ = 200
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression201 = Compression201
instance CompressionC Compression201 where
    compressionCID _ = 201
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression202 = Compression202
instance CompressionC Compression202 where
    compressionCID _ = 202
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression203 = Compression203
instance CompressionC Compression203 where
    compressionCID _ = 203
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression204 = Compression204
instance CompressionC Compression204 where
    compressionCID _ = 204
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression205 = Compression205
instance CompressionC Compression205 where
    compressionCID _ = 205
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression206 = Compression206
instance CompressionC Compression206 where
    compressionCID _ = 206
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression207 = Compression207
instance CompressionC Compression207 where
    compressionCID _ = 207
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression208 = Compression208
instance CompressionC Compression208 where
    compressionCID _ = 208
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression209 = Compression209
instance CompressionC Compression209 where
    compressionCID _ = 209
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression210 = Compression210
instance CompressionC Compression210 where
    compressionCID _ = 210
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression211 = Compression211
instance CompressionC Compression211 where
    compressionCID _ = 211
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression212 = Compression212
instance CompressionC Compression212 where
    compressionCID _ = 212
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression213 = Compression213
instance CompressionC Compression213 where
    compressionCID _ = 213
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression214 = Compression214
instance CompressionC Compression214 where
    compressionCID _ = 214
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression215 = Compression215
instance CompressionC Compression215 where
    compressionCID _ = 215
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression216 = Compression216
instance CompressionC Compression216 where
    compressionCID _ = 216
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression217 = Compression217
instance CompressionC Compression217 where
    compressionCID _ = 217
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression218 = Compression218
instance CompressionC Compression218 where
    compressionCID _ = 218
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression219 = Compression219
instance CompressionC Compression219 where
    compressionCID _ = 219
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression220 = Compression220
instance CompressionC Compression220 where
    compressionCID _ = 220
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression221 = Compression221
instance CompressionC Compression221 where
    compressionCID _ = 221
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression222 = Compression222
instance CompressionC Compression222 where
    compressionCID _ = 222
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression223 = Compression223
instance CompressionC Compression223 where
    compressionCID _ = 223
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression224 = Compression224
instance CompressionC Compression224 where
    compressionCID _ = 224
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression225 = Compression225
instance CompressionC Compression225 where
    compressionCID _ = 225
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression226 = Compression226
instance CompressionC Compression226 where
    compressionCID _ = 226
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression227 = Compression227
instance CompressionC Compression227 where
    compressionCID _ = 227
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression228 = Compression228
instance CompressionC Compression228 where
    compressionCID _ = 228
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression229 = Compression229
instance CompressionC Compression229 where
    compressionCID _ = 229
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression230 = Compression230
instance CompressionC Compression230 where
    compressionCID _ = 230
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression231 = Compression231
instance CompressionC Compression231 where
    compressionCID _ = 231
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression232 = Compression232
instance CompressionC Compression232 where
    compressionCID _ = 232
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression233 = Compression233
instance CompressionC Compression233 where
    compressionCID _ = 233
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression234 = Compression234
instance CompressionC Compression234 where
    compressionCID _ = 234
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression235 = Compression235
instance CompressionC Compression235 where
    compressionCID _ = 235
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression236 = Compression236
instance CompressionC Compression236 where
    compressionCID _ = 236
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression237 = Compression237
instance CompressionC Compression237 where
    compressionCID _ = 237
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression238 = Compression238
instance CompressionC Compression238 where
    compressionCID _ = 238
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression239 = Compression239
instance CompressionC Compression239 where
    compressionCID _ = 239
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression240 = Compression240
instance CompressionC Compression240 where
    compressionCID _ = 240
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression241 = Compression241
instance CompressionC Compression241 where
    compressionCID _ = 241
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression242 = Compression242
instance CompressionC Compression242 where
    compressionCID _ = 242
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression243 = Compression243
instance CompressionC Compression243 where
    compressionCID _ = 243
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression244 = Compression244
instance CompressionC Compression244 where
    compressionCID _ = 244
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression245 = Compression245
instance CompressionC Compression245 where
    compressionCID _ = 245
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression246 = Compression246
instance CompressionC Compression246 where
    compressionCID _ = 246
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression247 = Compression247
instance CompressionC Compression247 where
    compressionCID _ = 247
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression248 = Compression248
instance CompressionC Compression248 where
    compressionCID _ = 248
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression249 = Compression249
instance CompressionC Compression249 where
    compressionCID _ = 249
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression250 = Compression250
instance CompressionC Compression250 where
    compressionCID _ = 250
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression251 = Compression251
instance CompressionC Compression251 where
    compressionCID _ = 251
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression252 = Compression252
instance CompressionC Compression252 where
    compressionCID _ = 252
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression253 = Compression253
instance CompressionC Compression253 where
    compressionCID _ = 253
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression254 = Compression254
instance CompressionC Compression254 where
    compressionCID _ = 254
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)

data Compression255 = Compression255
instance CompressionC Compression255 where
    compressionCID _ = 255
    compressionCDeflate s b = (s, b)
    compressionCInflate s b = (s, b)
