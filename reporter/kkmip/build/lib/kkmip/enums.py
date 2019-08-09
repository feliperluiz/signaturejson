from __future__ import (print_function, division, unicode_literals, absolute_import)
from enum import Enum


class Format(Enum):
    TTLV = 0x01
    JSON = 0x02
    XML = 0x03


class MaskEnum(Enum):
    def __or__(self, other):
        if isinstance(other, MaskEnum):
            return self.value | other.value
        return self.value | other

    __ror__ = __or__


class ItemType(Enum):
    Structure = 0x01
    Integer = 0x02
    LongInteger = 0x03
    BigInteger = 0x04
    Enumeration = 0x05
    Boolean = 0x06
    TextString = 0x07
    ByteString = 0x08
    DateTime = 0x09
    Interval = 0x0A


class Tag(Enum):
    ActivationDate = 0x420001
    ApplicationData = 0x420002
    ApplicationNamespace = 0x420003
    ApplicationSpecificInformation = 0x420004
    ArchiveDate = 0x420005
    AsynchronousCorrelationValue = 0x420006
    AsynchronousIndicator = 0x420007
    Attribute = 0x420008
    AttributeIndex = 0x420009
    AttributeName = 0x42000A
    AttributeValue = 0x42000B
    Authentication = 0x42000C
    BatchCount = 0x42000D
    BatchErrorContinuationOption = 0x42000E
    BatchItem = 0x42000F
    BatchOrderOption = 0x420010
    BlockCipherMode = 0x420011
    CancellationResult = 0x420012
    Certificate = 0x420013
    CertificateIdentifier = 0x420014
    CertificateIssuer = 0x420015
    CertificateIssuerAlternativeName = 0x420016
    CertificateIssuerDistinguishedName = 0x420017
    CertificateRequest = 0x420018
    CertificateRequestType = 0x420019
    CertificateSubject = 0x42001A
    CertificateSubjectAlternativeName = 0x42001B
    CertificateSubjectDistinguishedName = 0x42001C
    CertificateType = 0x42001D
    CertificateValue = 0x42001E
    CommonTemplateAttribute = 0x42001F
    CompromiseDate = 0x420020
    CompromiseOccurrenceDate = 0x420021
    ContactInformation = 0x420022
    Credential = 0x420023
    CredentialType = 0x420024
    CredentialValue = 0x420025
    CriticalityIndicator = 0x420026
    CRTCoefficient = 0x420027
    CryptographicAlgorithm = 0x420028
    CryptographicDomainParameters = 0x420029
    CryptographicLength = 0x42002A
    CryptographicParameters = 0x42002B
    CryptographicUsageMask = 0x42002C
    CustomAttribute = 0x42002D
    D = 0x42002E
    DeactivationDate = 0x42002F
    DerivationData = 0x420030
    DerivationMethod = 0x420031
    DerivationParameters = 0x420032
    DestroyDate = 0x420033
    Digest = 0x420034
    DigestValue = 0x420035
    EncryptionKeyInformation = 0x420036
    G = 0x420037
    HashingAlgorithm = 0x420038
    InitialDate = 0x420039
    InitializationVector = 0x42003A
    Issuer = 0x42003B
    IterationCount = 0x42003C
    IVCounterNonce = 0x42003D
    J = 0x42003E
    Key = 0x42003F
    KeyBlock = 0x420040
    KeyCompressionType = 0x420041
    KeyFormatType = 0x420042
    KeyMaterial = 0x420043
    KeyPartIdentifier = 0x420044
    KeyValue = 0x420045
    KeyWrappingData = 0x420046
    KeyWrappingSpecification = 0x420047
    LastChangeDate = 0x420048
    LeaseTime = 0x420049
    Link = 0x42004A
    LinkType = 0x42004B
    LinkedObjectIdentifier = 0x42004C
    MACSignature = 0x42004D
    MACSignatureKeyInformation = 0x42004E
    MaximumItems = 0x42004F
    MaximumResponseSize = 0x420050
    MessageExtension = 0x420051
    Modulus = 0x420052
    Name = 0x420053
    NameType = 0x420054
    NameValue = 0x420055
    ObjectGroup = 0x420056
    ObjectType = 0x420057
    Offset = 0x420058
    OpaqueDataType = 0x420059
    OpaqueDataValue = 0x42005A
    OpaqueObject = 0x42005B
    Operation = 0x42005C
    OperationPolicyName = 0x42005D
    P = 0x42005E
    PaddingMethod = 0x42005F
    PrimeExponentP = 0x420060
    PrimeExponentQ = 0x420061
    PrimeFieldSize = 0x420062
    PrivateExponent = 0x420063
    PrivateKey = 0x420064
    PrivateKeyTemplateAttribute = 0x420065
    PrivateKeyUniqueIdentifier = 0x420066
    ProcessStartDate = 0x420067
    ProtectStopDate = 0x420068
    ProtocolVersion = 0x420069
    ProtocolVersionMajor = 0x42006A
    ProtocolVersionMinor = 0x42006B
    PublicExponent = 0x42006C
    PublicKey = 0x42006D
    PublicKeyTemplateAttribute = 0x42006E
    PublicKeyUniqueIdentifier = 0x42006F
    PutFunction = 0x420070
    Q = 0x420071
    QString = 0x420072
    Qlength = 0x420073
    QueryFunction = 0x420074
    RecommendedCurve = 0x420075
    ReplacedUniqueIdentifier = 0x420076
    RequestHeader = 0x420077
    RequestMessage = 0x420078
    RequestPayload = 0x420079
    ResponseHeader = 0x42007A
    ResponseMessage = 0x42007B
    ResponsePayload = 0x42007C
    ResultMessage = 0x42007D
    ResultReason = 0x42007E
    ResultStatus = 0x42007F
    RevocationMessage = 0x420080
    RevocationReason = 0x420081
    RevocationReasonCode = 0x420082
    KeyRoleType = 0x420083
    Salt = 0x420084
    SecretData = 0x420085
    SecretDataType = 0x420086
    SerialNumber = 0x420087
    ServerInformation = 0x420088
    SplitKey = 0x420089
    SplitKeyMethod = 0x42008A
    SplitKeyParts = 0x42008B
    SplitKeyThreshold = 0x42008C
    State = 0x42008D
    StorageStatusMask = 0x42008E
    SymmetricKey = 0x42008F
    Template = 0x420090
    TemplateAttribute = 0x420091
    TimeStamp = 0x420092
    UniqueBatchItemID = 0x420093
    UniqueIdentifier = 0x420094
    UsageLimits = 0x420095
    UsageLimitsCount = 0x420096
    UsageLimitsTotal = 0x420097
    UsageLimitsUnit = 0x420098
    Username = 0x420099
    ValidityDate = 0x42009A
    ValidityIndicator = 0x42009B
    VendorExtension = 0x42009C
    VendorIdentification = 0x42009D
    WrappingMethod = 0x42009E
    X = 0x42009F
    Y = 0x4200A0
    Password = 0x4200A1
    DeviceIdentifier = 0x4200A2
    EncodingOption = 0x4200A3
    ExtensionInformation = 0x4200A4
    ExtensionName = 0x4200A5
    ExtensionTag = 0x4200A6
    ExtensionType = 0x4200A7
    Fresh = 0x4200A8
    MachineIdentifier = 0x4200A9
    MediaIdentifier = 0x4200AA
    NetworkIdentifier = 0x4200AB
    ObjectGroupMember = 0x4200AC
    CertificateLength = 0x4200AD
    DigitalSignatureAlgorithm = 0x4200AE
    CertificateSerialNumber = 0x4200AF
    DeviceSerialNumber = 0x4200B0
    IssuerAlternativeName = 0x4200B1
    IssuerDistinguishedName = 0x4200B2
    SubjectAlternativeName = 0x4200B3
    SubjectDistinguishedName = 0x4200B4
    X_509CertificateIdentifier = 0x4200B5
    X_509CertificateIssuer = 0x4200B6
    X_509CertificateSubject = 0x4200B7
    KeyValueLocation = 0x4200B8
    KeyValueLocationValue = 0x4200B9
    KeyValueLocationType = 0x4200BA
    KeyValuePresent = 0x4200BB
    OriginalCreationDate = 0x4200BC
    PGPKey = 0x4200BD
    PGPKeyVersion = 0x4200BE
    AlternativeName = 0x4200BF
    AlternativeNameValue = 0x4200C0
    AlternativeNameType = 0x4200C1
    Data = 0x4200C2
    SignatureData = 0x4200C3
    DataLength = 0x4200C4
    RandomIV = 0x4200C5
    MACData = 0x4200C6
    AttestationType = 0x4200C7
    Nonce = 0x4200C8
    NonceID = 0x4200C9
    NonceValue = 0x4200CA
    AttestationMeasurement = 0x4200CB
    AttestationAssertion = 0x4200CC
    IVLength = 0x4200CD
    TagLength = 0x4200CE
    FixedFieldLength = 0x4200CF
    CounterLength = 0x4200D0
    InitialCounterValue = 0x4200D1
    InvocationFieldLength = 0x4200D2
    AttestationCapableIndicator = 0x4200D3
    OffsetItems = 0x4200D4
    LocatedItems = 0x4200D5
    CorrelationValue = 0x4200D6
    InitIndicator = 0x4200D7
    FinalIndicator = 0x4200D8
    RNGParameters = 0x4200D9
    RNGAlgorithm = 0x4200DA
    DRBGAlgorithm = 0x4200DB
    FIPS186Variation = 0x4200DC
    PredictionResistance = 0x4200DD
    RandomNumberGenerator = 0x4200DE
    ValidationInformation = 0x4200DF
    ValidationAuthorityType = 0x4200E0
    ValidationAuthorityCountry = 0x4200E1
    ValidationAuthorityURI = 0x4200E2
    ValidationVersionMajor = 0x4200E3
    ValidationVersionMinor = 0x4200E4
    ValidationType = 0x4200E5
    ValidationLevel = 0x4200E6
    ValidationCertificateIdentifier = 0x4200E7
    ValidationCertificateURI = 0x4200E8
    ValidationVendorURI = 0x4200E9
    ValidationProfile = 0x4200EA
    ProfileInformation = 0x4200EB
    ProfileName = 0x4200EC
    ServerURI = 0x4200ED
    ServerPort = 0x4200EE
    StreamingCapability = 0x4200EF
    AsynchronousCapability = 0x4200F0
    AttestationCapability = 0x4200F1
    UnwrapMode = 0x4200F2
    DestroyAction = 0x4200F3
    ShreddingAlgorithm = 0x4200F4
    RNGMode = 0x4200F5
    ClientRegistrationMethod = 0x4200F6
    CapabilityInformation = 0x4200F7
    KeyWrapType = 0x4200F8
    BatchUndoCapability = 0x4200F9
    BatchContinueCapability = 0x4200FA
    PKCS_12FriendlyName = 0x4200FB
    AuthenticatedEncryptionAdditionalData = 0x4200FE
    AuthenticatedEncryptionTag = 0x4200FF
    SaltLength = 0x420100
    MaskGenerator = 0x420101
    MaskGeneratorHashingAlgorithm = 0x420102
    PSource = 0x420103
    ClientCorrelationValue = 0x420105
    ServerCorrelationValue = 0x420106
    Sensitive = 0x420120
    AlwaysSensitive = 0x420121
    Extractable = 0x420122
    NeverExtractable = 0x420123
    FileData = 0x540000
    FileType = 0x540001
    FileDataDigest = 0x540002
    SEApplicationState = 0x540003
    StartNow = 0x540004
    StartOnBoot = 0x540005
    ApplicationEntryPoint = 0x540006
    ApplicationBasicInfo = 0x540007
    ApplicationName = 0x540008
    ApplicationRunning = 0x540009
    ApplicationArgument = 0x54000A
    InstanceIdentifier = 0x54000B
    ApplicationInstanceInfo = 0x54000C
    ClearHomeDirectory = 0x54000D
    ClearVarDirectory = 0x54000E
    ClearTmpDirectory = 0x54000F
    NonStop = 0x540010
    Restart = 0x540011
    LanInterface = 0x540012
    LanIP = 0x540013
    LanMask = 0x540014
    LanGateway = 0x540015
    LanDNS = 0x540016
    Year = 0x540017
    Month = 0x540018
    Day = 0x540019
    Hour = 0x54001A
    Minute = 0x54001B
    Second = 0x54001C
    Timezone = 0x54001D
    VHSMName = 0x54001E
    TTLVPort = 0x54001F
    HTTPSPort = 0x540020
    VHSMOptions = 0x540021
    VHSMUniqueID = 0x540022
    VCOPin = 0x540023
    InstanceIP = 0x540024
    UserName = 0x540025
    PermissionMask = 0x540026
    VCOName = 0x540027
    UserType = 0x540028
    PIN = 0x540029
    ImageData = 0x54002A
    ApplicationPort = 0x54002B
    ExternalPort = 0x54002C
    InternalPort = 0x54002D
    PortRangeStart = 0x54002E
    PortRangeEnd = 0x54002F
    KnetRSAPrivateKey = 0x540030
    DataPath = 0x540031
    SourceDir = 0x540032
    RelativePath = 0x540033
    SEApplicationData = 0x540034
    OldPassword = 0x540035
    NewPassword = 0x540036
    VirtualHSMData = 0x540037
    Active = 0x540038
    LanInterfaceInformation = 0x540039
    UserInformation = 0x54003A
    KnetECPrivateKey = 0x54003B
    UserCertificateRequest = 0x54003C
    UserCertificate = 0x54003D
    CACertificate = 0x54003E
    Usage = 0x54003F
    VHSMUsage = 0x540040
    CPU = 0x540041
    RAM = 0x540042
    Disk = 0x540043
    SELogRequest = 0x540044
    SELogResponse = 0x540045
    SEApplicationUsage = 0x540046
    FastSignRequest = 0x540047
    FastSignResponse = 0x540048
    LogLevel = 0x540049
    SEApplicationInstanceUsage = 0x54004A
    SELanguage = 0x54004B
    DeviceStatus = 0x54004C
    Version = 0x54004D
    Temperature = 0x54004E
    BatteryVoltage = 0x54004F
    MonitorState = 0x540050
    IntrusionState = 0x540051
    KNETState = 0x540052
    FIPSActiveMode = 0x540053
    Major = 0x540054
    Minor = 0x540055
    Patch = 0x540056
    ServerCertificate = 0x540057
    FunctionName = 0x540058
    RemoveVHSMPortRange = 0x540059
    SystemDescription = 0x54005A
    SystemContact = 0x54005B
    SystemName = 0x54005C
    SystemLocation = 0x54005D
    SystemServices = 0x54005E
    KnetSerialNumber = 0x54005F
    KnetFirmwareVersion = 0x540060
    KnetHardwareVersion = 0x540061
    KnetModel = 0x540062
    KnetFIPSModeEnabled = 0x540063
    KnetMCT7ModeEnabled = 0x540064
    KnetPCIModeEnabled = 0x540065
    KnetLicenseID = 0x540066
    KnetPerfomanceLimit = 0x540067
    KnetVhsmEnabled = 0x540068
    KnetVhsmLimit = 0x540069
    KnetSecureExecutionEnabled = 0x54006A
    KnetNumberOfUsers = 0x54006B
    KnetNumberOfObjects = 0x54006C
    KnetTotalBytes = 0x54006D
    KnetAvailableBytes = 0x54006E
    KnetAllocatedBytes = 0x54006F
    KnetBusyTime = 0x540070
    KnetProcessorUsage = 0x540071
    KnetCommandCount = 0x540072
    KnetTemperature = 0x540073
    KnetIPInt1 = 0x540074
    KnetIPInt2 = 0x540075
    KnetVHSMsCreated = 0x540076
    KnetVHSMsAvailable = 0x540077
    KnetNetwork1Status = 0x540078
    KnetNetwork2Status = 0x540079
    KnetNetwork1Bandwidth = 0x54007A
    KnetNetwork2Bandwidth = 0x54007B
    KnetClientsConnected = 0x54007C
    KnetSelfTestResult = 0x54007D
    KnetSelfTestTime = 0x54007E
    KnetErrorCount = 0x54007F
    KnetAuthErrorCount = 0x540080


class CredentialType(Enum):
    UsernameAndPassword = 0x00000001
    Device = 0x00000002
    Attestation = 0x00000003
    ConnectionCertificate = 0x80000001


class KeyCompressionType(Enum):
    ECPublicKeyTypeUncompressed = 0x00000001
    ECPublicKeyTypeX9_62CompressedPrime = 0x00000002
    ECPublicKeyTypeX9_62CompressedChar2 = 0x00000003
    ECPublicKeyTypeX9_62Hybrid = 0x00000004


class KeyFormatType(Enum):
    Raw = 0x00000001
    Opaque = 0x00000002
    PKCS_1 = 0x00000003
    PKCS_8 = 0x00000004
    X_509 = 0x00000005
    ECPrivateKey = 0x00000006
    TransparentSymmetricKey = 0x00000007
    TransparentDSAPrivateKey = 0x00000008
    TransparentDSAPublicKey = 0x00000009
    TransparentRSAPrivateKey = 0x0000000A
    TransparentRSAPublicKey = 0x0000000B
    TransparentDHPrivateKey = 0x0000000C
    TransparentDHPublicKey = 0x0000000D
    TransparentECPrivateKey = 0x00000014
    TransparentECPublicKey = 0x00000015
    PKCS_12 = 0x00000016
    KnetPrivateKey = 0x80000001
    KnetPublicKey = 0x80000002
    KnetSymmetricKey = 0x80000003
    KnetSecretData = 0x80000004


class WrappingMethod(Enum):
    Encrypt = 0x00000001
    MACSign = 0x00000002
    EncryptThenMACSign = 0x00000003
    MACSignThenEncrypt = 0x00000004
    TR31 = 0x00000005


class RecommendedCurve(Enum):
    P_192 = 0x00000001
    K_163 = 0x00000002
    B_163 = 0x00000003
    P_224 = 0x00000004
    K_233 = 0x00000005
    B_233 = 0x00000006
    P_256 = 0x00000007
    K_283 = 0x00000008
    B_283 = 0x00000009
    P_384 = 0x0000000A
    K_409 = 0x0000000B
    B_409 = 0x0000000C
    P_521 = 0x0000000D
    K_571 = 0x0000000E
    B_571 = 0x0000000F
    SECP112R1 = 0x00000010
    SECP112R2 = 0x00000011
    SECP128R1 = 0x00000012
    SECP128R2 = 0x00000013
    SECP160K1 = 0x00000014
    SECP160R1 = 0x00000015
    SECP160R2 = 0x00000016
    SECP192K1 = 0x00000017
    SECP224K1 = 0x00000018
    SECP256K1 = 0x00000019
    SECT113R1 = 0x0000001A
    SECT113R2 = 0x0000001B
    SECT131R1 = 0x0000001C
    SECT131R2 = 0x0000001D
    SECT163R1 = 0x0000001E
    SECT193R1 = 0x0000001F
    SECT193R2 = 0x00000020
    SECT239K1 = 0x00000021
    ANSIX9P192V2 = 0x00000022
    ANSIX9P192V3 = 0x00000023
    ANSIX9P239V1 = 0x00000024
    ANSIX9P239V2 = 0x00000025
    ANSIX9P239V3 = 0x00000026
    ANSIX9C2PNB163V1 = 0x00000027
    ANSIX9C2PNB163V2 = 0x00000028
    ANSIX9C2PNB163V3 = 0x00000029
    ANSIX9C2PNB176V1 = 0x0000002A
    ANSIX9C2TNB191V1 = 0x0000002B
    ANSIX9C2TNB191V2 = 0x0000002C
    ANSIX9C2TNB191V3 = 0x0000002D
    ANSIX9C2PNB208W1 = 0x0000002E
    ANSIX9C2TNB239V1 = 0x0000002F
    ANSIX9C2TNB239V2 = 0x00000030
    ANSIX9C2TNB239V3 = 0x00000031
    ANSIX9C2PNB272W1 = 0x00000032
    ANSIX9C2PNB304W1 = 0x00000033
    ANSIX9C2TNB359V1 = 0x00000034
    ANSIX9C2PNB368W1 = 0x00000035
    ANSIX9C2TNB431R1 = 0x00000036
    BRAINPOOLP160R1 = 0x00000037
    BRAINPOOLP160T1 = 0x00000038
    BRAINPOOLP192R1 = 0x00000039
    BRAINPOOLP192T1 = 0x0000003A
    BRAINPOOLP224R1 = 0x0000003B
    BRAINPOOLP224T1 = 0x0000003C
    BRAINPOOLP256R1 = 0x0000003D
    BRAINPOOLP256T1 = 0x0000003E
    BRAINPOOLP320R1 = 0x0000003F
    BRAINPOOLP320T1 = 0x00000040
    BRAINPOOLP384R1 = 0x00000041
    BRAINPOOLP384T1 = 0x00000042
    BRAINPOOLP512R1 = 0x00000043
    BRAINPOOLP512T1 = 0x00000044


class CertificateType(Enum):
    X_509 = 0x00000001
    PGP = 0x00000002


class DigitalSignatureAlgorithm(Enum):
    MD2WithRSAEncryption = 0x00000001
    MD5WithRSAEncryption = 0x00000002
    SHA_1WithRSAEncryption = 0x00000003
    SHA_224WithRSAEncryption = 0x00000004
    SHA_256WithRSAEncryption = 0x00000005
    SHA_384WithRSAEncryption = 0x00000006
    SHA_512WithRSAEncryption = 0x00000007
    RSASSA_PSS = 0x00000008
    DSAWithSHA_1 = 0x00000009
    DSAWithSHA224 = 0x0000000A
    DSAWithSHA256 = 0x0000000B
    ECDSAWithSHA_1 = 0x0000000C
    ECDSAWithSHA224 = 0x0000000D
    ECDSAWithSHA256 = 0x0000000E
    ECDSAWithSHA384 = 0x0000000F
    ECDSAWithSHA512 = 0x00000010


class SplitKeyMethod(Enum):
    XOR = 0x00000001
    PolynomialSharingGF2_16 = 0x00000002
    PolynomialSharingPrimeField = 0x00000003
    PolynomialSharingGF2_8 = 0x00000004


class SecretDataType(Enum):
    Password = 0x00000001
    Seed = 0x00000002


class NameType(Enum):
    UninterpretedTextString = 0x00000001
    URI = 0x00000002


class ObjectType(Enum):
    Certificate = 0x00000001
    SymmetricKey = 0x00000002
    PublicKey = 0x00000003
    PrivateKey = 0x00000004
    SplitKey = 0x00000005
    Template = 0x00000006
    SecretData = 0x00000007
    OpaqueObject = 0x00000008
    PGPKey = 0x00000009


class CryptographicAlgorithm(Enum):
    DES = 0x00000001
    DES3 = 0x00000002
    AES = 0x00000003
    RSA = 0x00000004
    DSA = 0x00000005
    ECDSA = 0x00000006
    HMAC_SHA1 = 0x00000007
    HMAC_SHA224 = 0x00000008
    HMAC_SHA256 = 0x00000009
    HMAC_SHA384 = 0x0000000A
    HMAC_SHA512 = 0x0000000B
    HMAC_MD5 = 0x0000000C
    DH = 0x0000000D
    ECDH = 0x0000000E
    ECMQV = 0x0000000F
    Blowfish = 0x00000010
    Camellia = 0x00000011
    CAST5 = 0x00000012
    IDEA = 0x00000013
    MARS = 0x00000014
    RC2 = 0x00000015
    RC4 = 0x00000016
    RC5 = 0x00000017
    SKIPJACK = 0x00000018
    Twofish = 0x00000019
    EC = 0x0000001A
    OneTimePad = 0x0000001B


class BlockCipherMode(Enum):
    CBC = 0x00000001
    ECB = 0x00000002
    PCBC = 0x00000003
    CFB = 0x00000004
    OFB = 0x00000005
    CTR = 0x00000006
    CMAC = 0x00000007
    CCM = 0x00000008
    GCM = 0x00000009
    CBC_MAC = 0x0000000A
    XTS = 0x0000000B
    AESKeyWrapPadding = 0x0000000C
    NISTKeyWrap = 0x0000000D
    X9_102AESKW = 0x0000000E
    X9_102TDKW = 0x0000000F
    X9_102AKW1 = 0x00000010
    X9_102AKW2 = 0x00000011


class PaddingMethod(Enum):
    NONE = 0x00000001
    OAEP = 0x00000002
    PKCS5 = 0x00000003
    SSL3 = 0x00000004
    Zeros = 0x00000005
    ANSIX9_23 = 0x00000006
    ISO10126 = 0x00000007
    PKCS1V1_5 = 0x00000008
    X9_31 = 0x00000009
    PSS = 0x0000000A


class HashingAlgorithm(Enum):
    MD2 = 0x00000001
    MD4 = 0x00000002
    MD5 = 0x00000003
    SHA_1 = 0x00000004
    SHA_224 = 0x00000005
    SHA_256 = 0x00000006
    SHA_384 = 0x00000007
    SHA_512 = 0x00000008
    RIPEMD_160 = 0x00000009
    Tiger = 0x0000000A
    Whirlpool = 0x0000000B
    SHA_512_224 = 0x0000000C
    SHA_512_256 = 0x0000000D


class KeyRoleType(Enum):
    BDK = 0x00000001
    CVK = 0x00000002
    DEK = 0x00000003
    MKAC = 0x00000004
    MKSMC = 0x00000005
    MKSMI = 0x00000006
    MKDAC = 0x00000007
    MKDN = 0x00000008
    MKCP = 0x00000009
    MKOTH = 0x0000000A
    KEK = 0x0000000B
    MAC16609 = 0x0000000C
    MAC97971 = 0x0000000D
    MAC97972 = 0x0000000E
    MAC97973 = 0x0000000F
    MAC97974 = 0x00000010
    MAC97975 = 0x00000011
    ZPK = 0x00000012
    PVKIBM = 0x00000013
    PVKPVV = 0x00000014
    PVKOTH = 0x00000015


class State(Enum):
    PreActive = 0x00000001
    Active = 0x00000002
    Deactivated = 0x00000003
    Compromised = 0x00000004
    Destroyed = 0x00000005
    DestroyedCompromised = 0x00000006


class RevocationReasonCode(Enum):
    Unspecified = 0x00000001
    KeyCompromise = 0x00000002
    CACompromise = 0x00000003
    AfiliationChanged = 0x00000004
    Superseded = 0x00000005
    CessationOfOperation = 0x00000006
    PrivilegeWithdrawn = 0x00000007


class LinkType(Enum):
    CertificateLink = 0x00000101
    PublicKeyLink = 0x00000102
    PrivateKeyLink = 0x00000103
    DerivationBaseObjectLink = 0x00000104
    DerivedKeyLink = 0x00000105
    ReplacementObjectLink = 0x00000106
    ReplacedObjectLink = 0x00000107
    ParentLink = 0x00000108
    ChildLink = 0x00000109
    PreviousLink = 0x0000010A
    NextLink = 0x0000010B
    PKCS_12CertificateLink = 0x0000010C
    PKCS_12PasswordLink = 0x0000010D


class ValidityIndicator(Enum):
    Valid = 0x00000001
    Invalid = 0x00000002
    Unknown = 0x00000003


class QueryFunction(Enum):
    QueryOperations = 0x00000001
    QueryObjects = 0x00000002
    QueryServerInformation = 0x00000003
    QueryApplicationNamespaces = 0x00000004
    QueryExtensionList = 0x00000005
    QueryExtensionMap = 0x00000006
    QueryAttestationTypes = 0x00000007
    QueryRNGs = 0x00000008
    QueryValidations = 0x00000009
    QueryProfiles = 0x0000000A
    QueryCapabilities = 0x0000000B
    QueryClientRegistrationMethods = 0x0000000C


class PutFunction(Enum):
    New = 0x00000001
    Replace = 0x00000002


class Operation(Enum):
    Create = 0x00000001
    CreateKeyPair = 0x00000002
    Register = 0x00000003
    ReKey = 0x00000004
    DeriveKey = 0x00000005
    Certify = 0x00000006
    ReCertify = 0x00000007
    Locate = 0x00000008
    Check = 0x00000009
    Get = 0x0000000A
    GetAttributes = 0x0000000B
    GetAttributeList = 0x0000000C
    AddAttribute = 0x0000000D
    ModifyAttribute = 0x0000000E
    DeleteAttribute = 0x0000000F
    ObtainLease = 0x00000010
    GetUsageAllocation = 0x00000011
    Activate = 0x00000012
    Revoke = 0x00000013
    Destroy = 0x00000014
    Archive = 0x00000015
    Recover = 0x00000016
    Validate = 0x00000017
    Query = 0x00000018
    Cancel = 0x00000019
    Poll = 0x0000001A
    Notify = 0x0000001B
    Put = 0x0000001C
    ReKeyKeyPair = 0x0000001D
    DiscoverVersions = 0x0000001E
    Encrypt = 0x0000001F
    Decrypt = 0x00000020
    Sign = 0x00000021
    SignatureVerify = 0x00000022
    MAC = 0x00000023
    MACVerify = 0x00000024
    RNGRetrieve = 0x00000025
    RNGSeed = 0x00000026
    Hash = 0x00000027
    CreateSplitKey = 0x00000028
    JoinSplitKey = 0x00000029
    RegisterSEApplication = 0x80000000
    GetSEApplicationState = 0x80000001
    CallSEApplicationCommand = 0x80000002
    ListSEApplications = 0x80000003
    StopSEApplication = 0x80000004
    DeleteSEApplication = 0x80000005
    StartSEApplication = 0x80000006
    RestartSEApplication = 0x80000007
    OverwriteSEApplication = 0x80000008
    ClearSEApplicationDirectory = 0x80000009
    ConfigureNetwork = 0x8000000A
    SetDateTime = 0x8000000B
    CreateVirtualHSM = 0x8000000C
    ActivateVirtualHSM = 0x8000000D
    DeactivateVirtualHSM = 0x8000000E
    DeleteVirtualHSM = 0x8000000F
    SetUserObjectPermission = 0x80000010
    GetUserObjectPermission = 0x80000011
    CreateUser = 0x80000012
    UploadLogoImage = 0x80000013
    GetRequesterType = 0x80000014
    CheckSEApplicationPortAvailable = 0x80000015
    RemoveSEApplicationInstance = 0x80000016
    GetSEApplicationData = 0x80000017
    ChangePassword = 0x80000018
    ListVirtualHSMs = 0x80000019
    GetDeviceTime = 0x8000001A
    GetNetworkConfiguration = 0x8000001B
    ListUsers = 0x8000001C
    RegisterCertificate = 0x8000001D
    ResetPassword = 0x8000001E
    FirmwareUpdate = 0x8000001F
    GetPHSMUsage = 0x80000020
    GetVHSMUsage = 0x80000021
    Shutdown = 0x80000022
    Restart = 0x80000023
    LoadKey = 0x80000024
    SetLogLevel = 0x80000025
    GetLogLevel = 0x80000026
    GetSEApplicationUsage = 0x80000027
    ExportVirtualHSM = 0x80000028
    ImportVirtualHSM = 0x80000029
    ImportPhysicalHSM = 0x8000002A
    ExportPhysicalHSM = 0x8000002B
    GetDeviceInformation = 0x8000002C
    GetTLSCertificate = 0x8000002D
    DeleteUser = 0x0000002E
    EditVirtualHSM = 0x8000002F
    GetSNMPData = 0x80000030
    SetSNMPData = 0x80000031
    GetSystemLog = 0x80000032


class ResultStatus(Enum):
    Success = 0x00000000
    OperationFailed = 0x00000001
    OperationPending = 0x00000002
    OperationUndone = 0x00000003


class ResultReason(Enum):
    ItemNotFound = 0x00000001
    ResponseTooLarge = 0x00000002
    AuthenticationNotSuccessful = 0x00000003
    InvalidMessage = 0x00000004
    OperationNotSupported = 0x00000005
    MissingData = 0x00000006
    InvalidField = 0x00000007
    FeatureNotSupported = 0x00000008
    OperationCanceledByRequester = 0x00000009
    CryptographicFailure = 0x0000000A
    IllegalOperation = 0x0000000B
    PermissionDenied = 0x0000000C
    ObjectArchived = 0x0000000D
    IndexOutOfBounds = 0x0000000E
    ApplicationNamespaceNotSupported = 0x0000000F
    KeyFormatTypeNotSupported = 0x00000010
    KeyCompressionTypeNotSupported = 0x00000011
    EncodingOptionError = 0x00000012
    KeyValueNotPresent = 0x00000013
    AttestationRequired = 0x00000014
    AttestationFailed = 0x00000015
    Sensitive = 0x00000016
    NotExtractable = 0x00000017
    GeneralFailure = 0x00000100


class BatchErrorContinuationOption(Enum):
    Continue = 0x00000001
    Stop = 0x00000002
    Undo = 0x00000003


class UsageLimitsUnit(Enum):
    Byte = 0x00000001
    Object = 0x00000002


class EncodingOption(Enum):
    NoEncoding = 0x00000001
    TTLVEncoding = 0x00000002


class ObjectGroupMember(Enum):
    GroupMemberFresh = 0x00000001
    GroupMemberDefault = 0x00000002


class AlternativeNameType(Enum):
    UninterpretedTextString = 0x00000001
    URI = 0x00000002
    ObjectSerialNumber = 0x00000003
    EmailAddress = 0x00000004
    DNSName = 0x00000005
    X_500DistinguishedName = 0x00000006
    IPAddress = 0x00000007


class KeyValueLocationType(Enum):
    UninterpretedTextString = 0x00000001
    URI = 0x00000002


class AttestationType(Enum):
    TPMQuote = 0x00000001
    TCGIntegrityReport = 0x00000002
    SAMLAssertion = 0x00000003


class RNGAlgorithm(Enum):
    Unspecified = 0x00000001
    FIPS186_2 = 0x00000002
    DRBG = 0x00000003
    NRBG = 0x00000004
    ANSIX9_31 = 0x00000005
    ANSIX9_62 = 0x00000006


class DRBGAlgorithm(Enum):
    Unspecified = 0x00000001
    Dual_EC = 0x00000002
    Hash = 0x00000003
    HMAC = 0x00000004
    CTR = 0x00000005


class FIPS186Variation(Enum):
    Unspecified = 0x00000001
    GPXOriginal = 0x00000002
    GPXChangeNotice = 0x00000003
    XOriginal = 0x00000004
    XChangeNotice = 0x00000005
    KOriginal = 0x00000006
    KChangeNotice = 0x00000007


class ValidationAuthorityType(Enum):
    Unspecified = 0x00000001
    NISTCMVP = 0x00000002
    CommonCriteria = 0x00000003


class ValidationType(Enum):
    Unspecified = 0x00000001
    Hardware = 0x00000002
    Software = 0x00000003
    Firmware = 0x00000004
    Hybrid = 0x00000005


class ProfileName(Enum):
    BaselineServerBasicKMIPv1_2 = 0x00000001
    BaselineServerTLSv1_2KMIPv1_2 = 0x00000002
    BaselineClientBasicKMIPv1_2 = 0x00000003
    BaselineClientTLSv1_2KMIPv1_2 = 0x00000004
    CompleteServerBasicKMIPv1_2 = 0x00000005
    CompleteServerTLSv1_2KMIPv1_2 = 0x00000006
    TapeLibraryClientKMIPv1_0 = 0x00000007
    TapeLibraryClientKMIPv1_1 = 0x00000008
    TapeLibraryClientKMIPv1_2 = 0x00000009
    TapeLibraryServerKMIPv1_0 = 0x0000000A
    TapeLibraryServerKMIPv1_1 = 0x0000000B
    TapeLibraryServerKMIPv1_2 = 0x0000000C
    SymmetricKeyLifecycleClientKMIPv1_0 = 0x0000000D
    SymmetricKeyLifecycleClientKMIPv1_1 = 0x0000000E
    SymmetricKeyLifecycleClientKMIPv1_2 = 0x0000000F
    SymmetricKeyLifecycleServerKMIPv1_0 = 0x00000010
    SymmetricKeyLifecycleServerKMIPv1_1 = 0x00000011
    SymmetricKeyLifecycleServerKMIPv1_2 = 0x00000012
    AsymmetricKeyLifecycleClientKMIPv1_0 = 0x00000013
    AsymmetricKeyLifecycleClientKMIPv1_1 = 0x00000014
    AsymmetricKeyLifecycleClientKMIPv1_2 = 0x00000015
    AsymmetricKeyLifecycleServerKMIPv1_0 = 0x00000016
    AsymmetricKeyLifecycleServerKMIPv1_1 = 0x00000017
    AsymmetricKeyLifecycleServerKMIPv1_2 = 0x00000018
    BasicCryptographicClientKMIPv1_2 = 0x00000019
    BasicCryptographicServerKMIPv1_2 = 0x0000001A
    AdvancedCryptographicClientKMIPv1_2 = 0x0000001B
    AdvancedCryptographicServerKMIPv1_2 = 0x0000001C
    RNGCryptographicClientKMIPv1_2 = 0x0000001D
    RNGCryptographicServerKMIPv1_2 = 0x0000001E
    BasicSymmetricKeyFoundryClientKMIPv1_0 = 0x0000001F
    IntermediateSymmetricKeyFoundryClientKMIPv1_0 = 0x00000020
    AdvancedSymmetricKeyFoundryClientKMIPv1_0 = 0x00000021
    BasicSymmetricKeyFoundryClientKMIPv1_1 = 0x00000022
    IntermediateSymmetricKeyFoundryClientKMIPv1_1 = 0x00000023
    AdvancedSymmetricKeyFoundryClientKMIPv1_1 = 0x00000024
    BasicSymmetricKeyFoundryClientKMIPv1_2 = 0x00000025
    IntermediateSymmetricKeyFoundryClientKMIPv1_2 = 0x00000026
    AdvancedSymmetricKeyFoundryClientKMIPv1_2 = 0x00000027
    SymmetricKeyFoundryServerKMIPv1_0 = 0x00000028
    SymmetricKeyFoundryServerKMIPv1_1 = 0x00000029
    SymmetricKeyFoundryServerKMIPv1_2 = 0x0000002A
    OpaqueManagedObjectStoreClientKMIPv1_0 = 0x0000002B
    OpaqueManagedObjectStoreClientKMIPv1_1 = 0x0000002C
    OpaqueManagedObjectStoreClientKMIPv1_2 = 0x0000002D
    OpaqueManagedObjectStoreServerKMIPv1_0 = 0x0000002E
    OpaqueManagedObjectStoreServerKMIPv1_1 = 0x0000002F
    OpaqueManagedObjectStoreServerKMIPv1_2 = 0x00000030
    SuiteBminLOS_128ClientKMIPv1_0 = 0x00000031
    SuiteBminLOS_128ClientKMIPv1_1 = 0x00000032
    SuiteBminLOS_128ClientKMIPv1_2 = 0x00000033
    SuiteBminLOS_128ServerKMIPv1_0 = 0x00000034
    SuiteBminLOS_128ServerKMIPv1_1 = 0x00000035
    SuiteBminLOS_128ServerKMIPv1_2 = 0x00000036
    SuiteBminLOS_192ClientKMIPv1_0 = 0x00000037
    SuiteBminLOS_192ClientKMIPv1_1 = 0x00000038
    SuiteBminLOS_192ClientKMIPv1_2 = 0x00000039
    SuiteBminLOS_192ServerKMIPv1_0 = 0x0000003A
    SuiteBminLOS_192ServerKMIPv1_1 = 0x0000003B
    SuiteBminLOS_192ServerKMIPv1_2 = 0x0000003C
    StorageArrayWithSelfEncryptingDriveClientKMIPv1_0 = 0x0000003D
    StorageArrayWithSelfEncryptingDriveClientKMIPv1_1 = 0x0000003E
    StorageArrayWithSelfEncryptingDriveClientKMIPv1_2 = 0x0000003F
    StorageArrayWithSelfEncryptingDriveServerKMIPv1_0 = 0x00000040
    StorageArrayWithSelfEncryptingDriveServerKMIPv1_1 = 0x00000041
    StorageArrayWithSelfEncryptingDriveServerKMIPv1_2 = 0x00000042
    HTTPSClientKMIPv1_0 = 0x00000043
    HTTPSClientKMIPv1_1 = 0x00000044
    HTTPSClientKMIPv1_2 = 0x00000045
    HTTPSServerKMIPv1_0 = 0x00000046
    HTTPSServerKMIPv1_1 = 0x00000047
    HTTPSServerKMIPv1_2 = 0x00000048
    JSONClientKMIPv1_0 = 0x00000049
    JSONClientKMIPv1_1 = 0x0000004A
    JSONClientKMIPv1_2 = 0x0000004B
    JSONServerKMIPv1_0 = 0x0000004C
    JSONServerKMIPv1_1 = 0x0000004D
    JSONServerKMIPv1_2 = 0x0000004E
    XMLClientKMIPv1_0 = 0x0000004F
    XMLClientKMIPv1_1 = 0x00000050
    XMLClientKMIPv1_2 = 0x00000051
    XMLServerKMIPv1_0 = 0x00000052
    XMLServerKMIPv1_1 = 0x00000053
    XMLServerKMIPv1_2 = 0x00000054
    BaselineServerBasicKMIPv1_3 = 0x00000055
    BaselineServerTLSv1_2KMIPv1_3 = 0x00000056
    BaselineClientBasicKMIPv1_3 = 0x00000057
    BaselineClientTLSv1_2KMIPv1_3 = 0x00000058
    CompleteServerBasicKMIPv1_3 = 0x00000059
    CompleteServerTLSv1_2KMIPv1_3 = 0x0000005A
    TapeLibraryClientKMIPv1_3 = 0x0000005B
    TapeLibraryServerKMIPv1_3 = 0x0000005C
    SymmetricKeyLifecycleClientKMIPv1_3 = 0x0000005D
    SymmetricKeyLifecycleServerKMIPv1_3 = 0x0000005E
    AsymmetricKeyLifecycleClientKMIPv1_3 = 0x0000005F
    AsymmetricKeyLifecycleServerKMIPv1_3 = 0x00000060
    BasicCryptographicClientKMIPv1_3 = 0x00000061
    BasicCryptographicServerKMIPv1_3 = 0x00000062
    AdvancedCryptographicClientKMIPv1_3 = 0x00000063
    AdvancedCryptographicServerKMIPv1_3 = 0x00000064
    RNGCryptographicClientKMIPv1_3 = 0x00000065
    RNGCryptographicServerKMIPv1_3 = 0x00000066
    BasicSymmetricKeyFoundryClientKMIPv1_3 = 0x00000067
    IntermediateSymmetricKeyFoundryClientKMIPv1_3 = 0x00000068
    AdvancedSymmetricKeyFoundryClientKMIPv1_3 = 0x00000069
    SymmetricKeyFoundryServerKMIPv1_3 = 0x0000006A
    OpaqueManagedObjectStoreClientKMIPv1_3 = 0x0000006B
    OpaqueManagedObjectStoreServerKMIPv1_3 = 0x0000006C
    SuiteBminLOS_128ClientKMIPv1_3 = 0x0000006D
    SuiteBminLOS_128ServerKMIPv1_3 = 0x0000006E
    SuiteBminLOS_192ClientKMIPv1_3 = 0x0000006F
    SuiteBminLOS_192ServerKMIPv1_3 = 0x00000070
    StorageArrayWithSelfEncryptingDriveClientKMIPv1_3 = 0x00000071
    StorageArrayWithSelfEncryptingDriveServerKMIPv1_3 = 0x00000072
    HTTPSClientKMIPv1_3 = 0x00000073
    HTTPSServerKMIPv1_3 = 0x00000074
    JSONClientKMIPv1_3 = 0x00000075
    JSONServerKMIPv1_3 = 0x00000076
    XMLClientKMIPv1_3 = 0x00000077
    XMLServerKMIPv1_3 = 0x00000078
    BaselineServerBasicKMIPv1_4 = 0x00000079
    BaselineServerTLSv1_2KMIPv1_4 = 0x0000007A
    BaselineClientBasicKMIPv1_4 = 0x0000007B
    BaselineClientTLSv1_2KMIPv1_4 = 0x0000007C
    CompleteServerBasicKMIPv1_4 = 0x0000007D
    CompleteServerTLSv1_2KMIPv1_4 = 0x0000007E
    TapeLibraryClientKMIPv1_4 = 0x0000007F
    TapeLibraryServerKMIPv1_4 = 0x00000080
    SymmetricKeyLifecycleClientKMIPv1_4 = 0x00000081
    SymmetricKeyLifecycleServerKMIPv1_4 = 0x00000082
    AsymmetricKeyLifecycleClientKMIPv1_4 = 0x00000083
    AsymmetricKeyLifecycleServerKMIPv1_4 = 0x00000084
    BasicCryptographicClientKMIPv1_4 = 0x00000085
    BasicCryptographicServerKMIPv1_4 = 0x00000086
    AdvancedCryptographicClientKMIPv1_4 = 0x00000087
    AdvancedCryptographicServerKMIPv1_4 = 0x00000088
    RNGCryptographicClientKMIPv1_4 = 0x00000089
    RNGCryptographicServerKMIPv1_4 = 0x0000008A
    BasicSymmetricKeyFoundryClientKMIPv1_4 = 0x0000008B
    IntermediateSymmetricKeyFoundryClientKMIPv1_4 = 0x0000008C
    AdvancedSymmetricKeyFoundryClientKMIPv1_4 = 0x0000008D
    SymmetricKeyFoundryServerKMIPv1_4 = 0x0000008E
    OpaqueManagedObjectStoreClientKMIPv1_4 = 0x0000008F
    OpaqueManagedObjectStoreServerKMIPv1_4 = 0x00000090
    SuiteBminLOS_128ClientKMIPv1_4 = 0x00000091
    SuiteBminLOS_128ServerKMIPv1_4 = 0x00000092
    SuiteBminLOS_192ClientKMIPv1_4 = 0x00000093
    SuiteBminLOS_192ServerKMIPv1_4 = 0x00000094
    StorageArrayWithSelfEncryptingDriveClientKMIPv1_4 = 0x00000095
    StorageArrayWithSelfEncryptingDriveServerKMIPv1_4 = 0x00000096
    HTTPSClientKMIPv1_4 = 0x00000097
    HTTPSServerKMIPv1_4 = 0x00000098
    JSONClientKMIPv1_4 = 0x00000099
    JSONServerKMIPv1_4 = 0x0000009A
    XMLClientKMIPv1_4 = 0x0000009B
    XMLServerKMIPv1_4 = 0x0000009C


class UnwrapMode(Enum):
    Unspecified = 0x00000001
    Processed = 0x00000002
    NotProcessed = 0x00000003


class DestroyAction(Enum):
    Unspecified = 0x00000001
    KeyMaterialDeleted = 0x00000002
    KeyMaterialShredded = 0x00000003
    MetaDataDeleted = 0x00000004
    MetaDataShredded = 0x00000005
    Deleted = 0x00000006
    Shredded = 0x00000007


class ShreddingAlgorithm(Enum):
    Unspecified = 0x00000001
    Cryptographic = 0x00000002
    Unsupported = 0x00000003


class RNGMode(Enum):
    Unspecified = 0x00000001
    SharedInstantiation = 0x00000002
    NonSharedInstantiation = 0x00000003


class ClientRegistrationMethod(Enum):
    Unspecified = 0x00000001
    ServerPreGenerated = 0x00000002
    ServerOnDemand = 0x00000003
    ClientGenerated = 0x00000004
    ClientRegistered = 0x00000005


class KeyWrapType(Enum):
    NotWrapped = 0x00000001
    AsRegistered = 0x00000002


class MaskGenerator(Enum):
    MGF1 = 0x00000001


class CryptographicUsageMask(MaskEnum):
    Sign = 0x00000001
    Verify = 0x00000002
    Encrypt = 0x00000004
    Decrypt = 0x00000008
    WrapKey = 0x00000010
    UnwrapKey = 0x00000020
    Export = 0x00000040
    MACGenerate = 0x00000080
    MACVerify = 0x00000100
    DeriveKey = 0x00000200
    ContentCommitment = 0x00000400
    KeyAgreement = 0x00000800
    CertificateSign = 0x00001000
    CRLSign = 0x00002000
    GenerateCryptogram = 0x00004000
    ValidateCryptogram = 0x00008000
    TranslateEncrypt = 0x00010000
    TranslateDecrypt = 0x00020000
    TranslateWrap = 0x00040000
    TranslateUnwrap = 0x00080000


class StorageStatusMask(MaskEnum):
    OnLineStorage = 0x00000001
    ArchivalStorage = 0x00000002


class FileType(Enum):
    PythonScript = 0x00000001
    ZippedPythonApplication = 0x00000002
    TarGzPythonApplication = 0x00000003


class SEApplicationState(Enum):
    Started = 0x00000001


class UserType(Enum):
    Unknown = 0x00000000
    VCO = 0x00000001
    User = 0x00000002
    PCO = 0x00000003


class LanInterface(Enum):
    A = 0x00000000
    B = 0x00000001


class SourceDir(Enum):
    HOME = 0x00000001
    VAR = 0x00000002
    TMP = 0x00000003


class LogLevel(Enum):
    Off = 0x00000001
    Error = 0x00000002
    Info = 0x00000003
    Verbose = 0x00000004
    Complete = 0x00000005


class SELanguage(Enum):
    Python2 = 0x00000001
    Python3 = 0x00000002


class MonitorState(Enum):
    Nominal = 0x00000001
    Limp = 0x00000002


class IntrusionState(Enum):
    Nominal = 0x00000001
    Tampered = 0x00000002


class KNETState(Enum):
    Factory = 0x00000001
    SemiOperational = 0x00000002
    Operational = 0x00000003
    Tampered = 0x00000004


class PermissionMask(MaskEnum):
    NoPermission = 0x00000000
    Owner = 0x00000001
    Usage = 0x00000002


