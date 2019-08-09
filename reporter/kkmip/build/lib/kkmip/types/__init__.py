from kkmip import enums
from kkmip.types.base import KmipObject, RequestPayload, ResponsePayload, AttributeValue, ManagedObject, MULTI, SINGLE, OPTIONAL, REQUIRED, MAYBE_REQUIRED
from kkmip.types.encoding import decode


__all__ = ['KmipObject', 'RequestPayload', 'ResponsePayload', 'AttributeValue', 'ManagedObject', 'decode']
# __all__ is complemented at the end of the file


class ActivateRequestPayload(RequestPayload):
    """
    ActivateRequestPayload is the payload of a Activate Operation Request message.
    
    Args:
        unique_identifier (str): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Activate

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(ActivateRequestPayload, self).__init__()


class ActivateResponsePayload(ResponsePayload):
    """
    ActivateResponsePayload is the payload of a Activate Operation Response message
    
    Args:
        unique_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.Activate

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(ActivateResponsePayload, self).__init__()


class ActivateVirtualHSMRequestPayload(RequestPayload):
    """
    ActivateVirtualHSMRequestPayload is the payload of an Activate VHSM Operation
    Request message.
    
    Args:
        vhsm_unique_id (int): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ActivateVirtualHSM

    def __init__(self, vhsm_unique_id=None):
        self.vhsm_unique_id = vhsm_unique_id
        super(ActivateVirtualHSMRequestPayload, self).__init__()


class ActivateVirtualHSMResponsePayload(ResponsePayload):
    """
    ActivateVirtualHSMResponsePayload is the payload of an Activate VHSM Operation
    Response message.
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.ActivateVirtualHSM

    def __init__(self):
        super(ActivateVirtualHSMResponsePayload, self).__init__()


class AddAttributeRequestPayload(RequestPayload):
    """
    AddAttributeRequestPayload is the payload of a Add Attribute Operation
    Request message
    
    Args:
        unique_identifier (str): optional
        attribute (types.Attribute): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("attribute", enums.Tag.Attribute, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.AddAttribute

    def __init__(self, unique_identifier=None, attribute=None):
        self.unique_identifier = unique_identifier
        self.attribute = attribute
        super(AddAttributeRequestPayload, self).__init__()


class AddAttributeResponsePayload(ResponsePayload):
    """
    AddAttributeResponsePayload is the payload of a Add Attribute Operation
    Response message
    
    Args:
        unique_identifier (str): required
        attribute (types.Attribute): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("attribute", enums.Tag.Attribute, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.AddAttribute

    def __init__(self, unique_identifier=None, attribute=None):
        self.unique_identifier = unique_identifier
        self.attribute = attribute
        super(AddAttributeResponsePayload, self).__init__()


class AlternativeName(AttributeValue):
    """
    AlternativeName is a structure used to identify and locate the object
    intended to be in a form that humans are able to interpret
    
    Args:
        alternative_name_value (str): required
        alternative_name_type (enums.AlternativeNameType): required
    """

    TAG = enums.Tag.AlternativeName
    FIELDS = [
        ("alternative_name_value", enums.Tag.AlternativeNameValue, SINGLE, REQUIRED),
        ("alternative_name_type", enums.Tag.AlternativeNameType, SINGLE, REQUIRED)
    ]

    def __init__(self, alternative_name_value=None, alternative_name_type=None):
        self.alternative_name_value = alternative_name_value
        self.alternative_name_type = alternative_name_type
        super(AlternativeName, self).__init__()


class ApplicationBasicInfo(KmipObject):
    """
    Applicatio Basic Info is a structure used to to receive information of a secure app
    
    Args:
        unique_identifier (str): required
        application_name (str): required
        application_instance_info_list (list(types.ApplicationInstanceInfo)): optional
        application_port_list (list(types.ApplicationPort)): optional
    """

    TAG = enums.Tag.ApplicationBasicInfo
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("application_name", enums.Tag.ApplicationName, SINGLE, REQUIRED),
        ("application_instance_info_list", enums.Tag.ApplicationInstanceInfo, MULTI, OPTIONAL),
        ("application_port_list", enums.Tag.ApplicationPort, MULTI, OPTIONAL)
    ]

    def __init__(self, unique_identifier=None, application_name=None, application_instance_info_list=None, application_port_list=None):
        self.unique_identifier = unique_identifier
        self.application_name = application_name
        self.application_instance_info_list = application_instance_info_list
        self.application_port_list = application_port_list
        super(ApplicationBasicInfo, self).__init__()


class ApplicationInstanceInfo(KmipObject):
    """
    Application Instance Info is a structure used to to receive information of a secure app
    
    Args:
        instance_identifier (str): required
        application_running (bool): required
        application_argument_list (list(str)): optional
        application_port_list (list(types.ApplicationPort)): optional
    """

    TAG = enums.Tag.ApplicationInstanceInfo
    FIELDS = [
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED),
        ("application_running", enums.Tag.ApplicationRunning, SINGLE, REQUIRED),
        ("application_argument_list", enums.Tag.ApplicationArgument, MULTI, OPTIONAL),
        ("application_port_list", enums.Tag.ApplicationPort, MULTI, OPTIONAL)
    ]

    def __init__(self, instance_identifier=None, application_running=None, application_argument_list=None, application_port_list=None):
        self.instance_identifier = instance_identifier
        self.application_running = application_running
        self.application_argument_list = application_argument_list
        self.application_port_list = application_port_list
        super(ApplicationInstanceInfo, self).__init__()


class ApplicationPort(KmipObject):
    """
    Application Port holds a pair of port numbers that will be mapped to each other.
    
    Args:
        external_port (int): required
        internal_port (int): required
    """

    TAG = enums.Tag.ApplicationPort
    FIELDS = [
        ("external_port", enums.Tag.ExternalPort, SINGLE, REQUIRED),
        ("internal_port", enums.Tag.InternalPort, SINGLE, REQUIRED)
    ]

    def __init__(self, external_port=None, internal_port=None):
        self.external_port = external_port
        self.internal_port = internal_port
        super(ApplicationPort, self).__init__()


class ApplicationSpecificInformation(AttributeValue):
    """
    ApplicationSpecificInformation attribute is a structure used to store data
    specific to the application using the Managed Object.
    
    Args:
        application_namespace (str): required
        application_data (str): optional
    """

    TAG = enums.Tag.ApplicationSpecificInformation
    FIELDS = [
        ("application_namespace", enums.Tag.ApplicationNamespace, SINGLE, REQUIRED),
        ("application_data", enums.Tag.ApplicationData, SINGLE, OPTIONAL)
    ]

    def __init__(self, application_namespace=None, application_data=None):
        self.application_namespace = application_namespace
        self.application_data = application_data
        super(ApplicationSpecificInformation, self).__init__()


class AttestationCredential(KmipObject):
    """
    AttestationCredential is the defined type for the value of Credential
    when the CredentialType is Attestation
    
    Args:
        nonce (types.Nonce): required
        attestation_type (enums.AttestationType): required
        attestation_measurement (bytes): optional
        attestation_assertion (bytes): optional
    """

    TAG = enums.Tag.CredentialValue
    FIELDS = [
        ("nonce", enums.Tag.Nonce, SINGLE, REQUIRED),
        ("attestation_type", enums.Tag.AttestationType, SINGLE, REQUIRED),
        ("attestation_measurement", enums.Tag.AttestationMeasurement, SINGLE, OPTIONAL),
        ("attestation_assertion", enums.Tag.AttestationAssertion, SINGLE, OPTIONAL)
    ]

    def __init__(self, nonce=None, attestation_type=None, attestation_measurement=None, attestation_assertion=None):
        self.nonce = nonce
        self.attestation_type = attestation_type
        self.attestation_measurement = attestation_measurement
        self.attestation_assertion = attestation_assertion
        super(AttestationCredential, self).__init__()


class Attribute(KmipObject):
    """
    Attribute object is a structure used to send and receiving Managed Object
    attributes.
    
    Args:
        attribute_name (str or enums.Tag): required. The attribute name or the attribute tag. If it is a tag, it must correspond to one of the KMIP attributes.
        attribute_index (int): optional
        attribute_value: optional

            :attr:`.Tag.UniqueIdentifier`: :obj:`str`

            :attr:`.Tag.Name`: :any:`types.Name`

            :attr:`.Tag.ObjectType`: :any:`enums.ObjectType`

            :attr:`.Tag.CryptographicAlgorithm`: :any:`enums.CryptographicAlgorithm`

            :attr:`.Tag.CryptographicLength`: :obj:`int`

            :attr:`.Tag.CryptographicParameters`: :any:`types.CryptographicParameters`

            :attr:`.Tag.CryptographicDomainParameters`: :any:`types.CryptographicDomainParameters`

            :attr:`.Tag.CertificateType`: :any:`enums.CertificateType`

            :attr:`.Tag.CertificateLength`: :obj:`int`

            :attr:`.Tag.X_509CertificateIdentifier`: :any:`types.X_509CertificateIdentifier`

            :attr:`.Tag.X_509CertificateSubject`: :any:`types.X_509CertificateSubject`

            :attr:`.Tag.X_509CertificateIssuer`: :any:`types.X_509CertificateIssuer`

            :attr:`.Tag.CertificateIdentifier`: :any:`types.CertificateIdentifier`

            :attr:`.Tag.CertificateSubject`: :any:`types.CertificateSubject`

            :attr:`.Tag.CertificateIssuer`: :any:`types.CertificateIssuer`

            :attr:`.Tag.DigitalSignatureAlgorithm`: :any:`enums.DigitalSignatureAlgorithm`

            :attr:`.Tag.Digest`: :any:`types.Digest`

            :attr:`.Tag.OperationPolicyName`: :obj:`str`

            :attr:`.Tag.CryptographicUsageMask`: :obj:`int`

            :attr:`.Tag.LeaseTime`: :obj:`datetime.timedelta`

            :attr:`.Tag.UsageLimits`: :any:`types.UsageLimits`

            :attr:`.Tag.State`: :any:`enums.State`

            :attr:`.Tag.InitialDate`: :obj:`datetime.datetime`

            :attr:`.Tag.ActivationDate`: :obj:`datetime.datetime`

            :attr:`.Tag.ProcessStartDate`: :obj:`datetime.datetime`

            :attr:`.Tag.ProtectStopDate`: :obj:`datetime.datetime`

            :attr:`.Tag.DeactivationDate`: :obj:`datetime.datetime`

            :attr:`.Tag.DestroyDate`: :obj:`datetime.datetime`

            :attr:`.Tag.CompromiseOccurrenceDate`: :obj:`datetime.datetime`

            :attr:`.Tag.CompromiseDate`: :obj:`datetime.datetime`

            :attr:`.Tag.RevocationReason`: :any:`types.RevocationReason`

            :attr:`.Tag.ArchiveDate`: :obj:`datetime.datetime`

            :attr:`.Tag.ObjectGroup`: :obj:`str`

            :attr:`.Tag.Fresh`: :obj:`bool`

            :attr:`.Tag.Link`: :any:`types.Link`

            :attr:`.Tag.ApplicationSpecificInformation`: :any:`types.ApplicationSpecificInformation`

            :attr:`.Tag.ContactInformation`: :obj:`str`

            :attr:`.Tag.LastChangeDate`: :obj:`datetime.datetime`

            :attr:`.Tag.AlternativeName`: :any:`types.AlternativeName`

            :attr:`.Tag.KeyValuePresent`: :obj:`bool`

            :attr:`.Tag.KeyValueLocation`: :any:`types.KeyValueLocation`

            :attr:`.Tag.OriginalCreationDate`: :obj:`datetime.datetime`

            :attr:`.Tag.Sensitive`: :obj:`bool`

            :attr:`.Tag.AlwaysSensitive`: :obj:`bool`

            :attr:`.Tag.Extractable`: :obj:`bool`

            :attr:`.Tag.NeverExtractable`: :obj:`bool`

    """

    TAG = enums.Tag.Attribute
    FIELDS = [
        ("attribute_name", enums.Tag.AttributeName, SINGLE, REQUIRED),
        ("attribute_index", enums.Tag.AttributeIndex, SINGLE, OPTIONAL),
        ("attribute_value", (enums.Tag.UniqueIdentifier, enums.Tag.Name, enums.Tag.ObjectType, enums.Tag.CryptographicAlgorithm, enums.Tag.CryptographicLength, enums.Tag.CryptographicParameters, enums.Tag.CryptographicDomainParameters, enums.Tag.CertificateType, enums.Tag.CertificateLength, enums.Tag.X_509CertificateIdentifier, enums.Tag.X_509CertificateSubject, enums.Tag.X_509CertificateIssuer, enums.Tag.CertificateIdentifier, enums.Tag.CertificateSubject, enums.Tag.CertificateIssuer, enums.Tag.DigitalSignatureAlgorithm, enums.Tag.Digest, enums.Tag.OperationPolicyName, enums.Tag.CryptographicUsageMask, enums.Tag.LeaseTime, enums.Tag.UsageLimits, enums.Tag.State, enums.Tag.InitialDate, enums.Tag.ActivationDate, enums.Tag.ProcessStartDate, enums.Tag.ProtectStopDate, enums.Tag.DeactivationDate, enums.Tag.DestroyDate, enums.Tag.CompromiseOccurrenceDate, enums.Tag.CompromiseDate, enums.Tag.RevocationReason, enums.Tag.ArchiveDate, enums.Tag.ObjectGroup, enums.Tag.Fresh, enums.Tag.Link, enums.Tag.ApplicationSpecificInformation, enums.Tag.ContactInformation, enums.Tag.LastChangeDate, enums.Tag.CustomAttribute, enums.Tag.AlternativeName, enums.Tag.KeyValuePresent, enums.Tag.KeyValueLocation, enums.Tag.OriginalCreationDate, enums.Tag.RandomNumberGenerator, enums.Tag.Sensitive, enums.Tag.AlwaysSensitive, enums.Tag.Extractable, enums.Tag.NeverExtractable,), SINGLE, MAYBE_REQUIRED)
    ]

    def __init__(self, attribute_name=None, attribute_index=None, attribute_value=None):
        self.attribute_name = attribute_name
        self.attribute_index = attribute_index
        self.attribute_value = attribute_value
        super(Attribute, self).__init__()


class Authentication(KmipObject):
    """
    Authentication is used to authenticate the requester
    
    Args:
        credential_list (list(types.Credential)): optional
    """

    TAG = enums.Tag.Authentication
    FIELDS = [
        ("credential_list", enums.Tag.Credential, MULTI, OPTIONAL)
    ]

    def __init__(self, credential_list=None):
        self.credential_list = credential_list
        super(Authentication, self).__init__()


class CallSEApplicationCommandRequestPayload(RequestPayload):
    """
    CallSEAppCommandRequestPayload is the payload of a Get SE
    State Operation Request message.
    
    Args:
        unique_identifier (str): required
        instance_identifier (str): required
        function_name (str): required
        data (bytes): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED),
        ("function_name", enums.Tag.FunctionName, SINGLE, REQUIRED),
        ("data", enums.Tag.Data, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.CallSEApplicationCommand

    def __init__(self, unique_identifier=None, instance_identifier=None, function_name=None, data=None):
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        self.function_name = function_name
        self.data = data
        super(CallSEApplicationCommandRequestPayload, self).__init__()


class CallSEApplicationCommandResponsePayload(ResponsePayload):
    """
    CallSEAppCommandResponsePayload is the payload of a Get SE
    State Operation Response message
    
    Args:
        unique_identifier (str): required
        data (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("data", enums.Tag.Data, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.CallSEApplicationCommand

    def __init__(self, unique_identifier=None, data=None):
        self.unique_identifier = unique_identifier
        self.data = data
        super(CallSEApplicationCommandResponsePayload, self).__init__()


class CapabilityInformation(KmipObject):
    """
    Capability Information base object contains details of supported capabilities
    
    Args:
        streaming_capability (bool): optional
        asynchronous_capability (bool): optional
        attestation_capability (bool): optional
        batch_undo_capability (bool): optional
        batch_continue_capability (bool): optional
        unwrap_mode (enums.UnwrapMode): optional
        destroy_action (enums.DestroyAction): optional
        shredding_algorithm (enums.ShreddingAlgorithm): optional
        rng_mode (enums.RNGMode): optional
    """

    TAG = enums.Tag.CapabilityInformation
    FIELDS = [
        ("streaming_capability", enums.Tag.StreamingCapability, SINGLE, OPTIONAL),
        ("asynchronous_capability", enums.Tag.AsynchronousCapability, SINGLE, OPTIONAL),
        ("attestation_capability", enums.Tag.AttestationCapability, SINGLE, OPTIONAL),
        ("batch_undo_capability", enums.Tag.BatchUndoCapability, SINGLE, OPTIONAL),
        ("batch_continue_capability", enums.Tag.BatchContinueCapability, SINGLE, OPTIONAL),
        ("unwrap_mode", enums.Tag.UnwrapMode, SINGLE, OPTIONAL),
        ("destroy_action", enums.Tag.DestroyAction, SINGLE, OPTIONAL),
        ("shredding_algorithm", enums.Tag.ShreddingAlgorithm, SINGLE, OPTIONAL),
        ("rng_mode", enums.Tag.RNGMode, SINGLE, OPTIONAL)
    ]

    def __init__(self, streaming_capability=None, asynchronous_capability=None, attestation_capability=None, batch_undo_capability=None, batch_continue_capability=None, unwrap_mode=None, destroy_action=None, shredding_algorithm=None, rng_mode=None):
        self.streaming_capability = streaming_capability
        self.asynchronous_capability = asynchronous_capability
        self.attestation_capability = attestation_capability
        self.batch_undo_capability = batch_undo_capability
        self.batch_continue_capability = batch_continue_capability
        self.unwrap_mode = unwrap_mode
        self.destroy_action = destroy_action
        self.shredding_algorithm = shredding_algorithm
        self.rng_mode = rng_mode
        super(CapabilityInformation, self).__init__()


class Certificate(ManagedObject):
    """
    Certificate is a digital certificate. It is a DER encoded X.509 public key
    certificate
    
    Args:
        certificate_type (enums.CertificateType): required
        certificate_value (bytes): required
    """

    TAG = enums.Tag.Certificate
    FIELDS = [
        ("certificate_type", enums.Tag.CertificateType, SINGLE, REQUIRED),
        ("certificate_value", enums.Tag.CertificateValue, SINGLE, REQUIRED)
    ]

    def __init__(self, certificate_type=None, certificate_value=None):
        self.certificate_type = certificate_type
        self.certificate_value = certificate_value
        super(Certificate, self).__init__()


class CertificateIdentifier(AttributeValue):
    """
    CertificateIdentifier is a struct used to provide the identification of
    a certificate.
    This attribute is deprecated as of version 1.1 of this specification and
    MAY be removed from subsequent versions of this specification.
    
    Args:
        issuer (str): required
        serial_number (str): optional
    """

    TAG = enums.Tag.CertificateIdentifier
    FIELDS = [
        ("issuer", enums.Tag.Issuer, SINGLE, REQUIRED),
        ("serial_number", enums.Tag.SerialNumber, SINGLE, MAYBE_REQUIRED)
    ]

    def __init__(self, issuer=None, serial_number=None):
        self.issuer = issuer
        self.serial_number = serial_number
        super(CertificateIdentifier, self).__init__()


class CertificateIssuer(AttributeValue):
    """
    CertificateIssuer is a structure used to identify the issuer of a
    certificate.
    This attribute is deprecated as of version 1.1 of this specification and
    MAY be removed from subsequent versions of this specification.
    
    Args:
        certificate_issuer_distinguished_name (str): optional
        certificate_issuer_alternative_name_list (list(str)): optional
    """

    TAG = enums.Tag.CertificateIssuer
    FIELDS = [
        ("certificate_issuer_distinguished_name", enums.Tag.CertificateIssuerDistinguishedName, SINGLE, MAYBE_REQUIRED),
        ("certificate_issuer_alternative_name_list", enums.Tag.CertificateIssuerAlternativeName, MULTI, OPTIONAL)
    ]

    def __init__(self, certificate_issuer_distinguished_name=None, certificate_issuer_alternative_name_list=None):
        self.certificate_issuer_distinguished_name = certificate_issuer_distinguished_name
        self.certificate_issuer_alternative_name_list = certificate_issuer_alternative_name_list
        super(CertificateIssuer, self).__init__()


class CertificateSubject(AttributeValue):
    """
    CertificateSubject is a structure used to identify the subject of a
    certificate.
    This attribute is deprecated as of version 1.1 of this specification and
    MAY be removed from subsequent versions of this specification.
    
    Args:
        certificate_subject_distinguished_name (str): optional
        certificate_subject_alternative_name_list (list(str)): optional
    """

    TAG = enums.Tag.CertificateSubject
    FIELDS = [
        ("certificate_subject_distinguished_name", enums.Tag.CertificateSubjectDistinguishedName, SINGLE, MAYBE_REQUIRED),
        ("certificate_subject_alternative_name_list", enums.Tag.CertificateSubjectAlternativeName, MULTI, OPTIONAL)
    ]

    def __init__(self, certificate_subject_distinguished_name=None, certificate_subject_alternative_name_list=None):
        self.certificate_subject_distinguished_name = certificate_subject_distinguished_name
        self.certificate_subject_alternative_name_list = certificate_subject_alternative_name_list
        super(CertificateSubject, self).__init__()


class ChangePasswordRequestPayload(RequestPayload):
    """
    ChangePasswordRequestPayload is the payload of a Change Password Operation
    Request message
    
    Args:
        old_password (str): required
        new_password (str): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("old_password", enums.Tag.OldPassword, SINGLE, REQUIRED),
        ("new_password", enums.Tag.NewPassword, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ChangePassword

    def __init__(self, old_password=None, new_password=None):
        self.old_password = old_password
        self.new_password = new_password
        super(ChangePasswordRequestPayload, self).__init__()


class ChangePasswordResponsePayload(ResponsePayload):
    """
    ChangePasswordResponsePayload is the payload of an Change Password Operation
    Response message.
    
    Args:
        certificate (types.Certificate): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("certificate", enums.Tag.Certificate, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ChangePassword

    def __init__(self, certificate=None):
        self.certificate = certificate
        super(ChangePasswordResponsePayload, self).__init__()


class CheckRequestPayload(RequestPayload):
    """
    CheckRequestPayload defines the payload of a Check Operation Request
    
    Args:
        unique_identifier (str): optional
        usage_limits_count (ttv.LongInteger): optional
        cryptographic_usage_mask (int): optional
        lease_time (datetime.timedelta): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("usage_limits_count", enums.Tag.UsageLimitsCount, SINGLE, OPTIONAL),
        ("cryptographic_usage_mask", enums.Tag.CryptographicUsageMask, SINGLE, OPTIONAL),
        ("lease_time", enums.Tag.LeaseTime, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Check

    def __init__(self, unique_identifier=None, usage_limits_count=None, cryptographic_usage_mask=None, lease_time=None):
        self.unique_identifier = unique_identifier
        self.usage_limits_count = usage_limits_count
        self.cryptographic_usage_mask = cryptographic_usage_mask
        self.lease_time = lease_time
        super(CheckRequestPayload, self).__init__()


class CheckResponsePayload(ResponsePayload):
    """
    CheckResponsePayload defines the payload of the response message for a
    Check Operation Request
    
    Args:
        unique_identifier (str): required
        usage_limits_count (ttv.LongInteger): optional
        cryptographic_usage_mask (int): optional
        lease_time (datetime.timedelta): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("usage_limits_count", enums.Tag.UsageLimitsCount, SINGLE, OPTIONAL),
        ("cryptographic_usage_mask", enums.Tag.CryptographicUsageMask, SINGLE, OPTIONAL),
        ("lease_time", enums.Tag.LeaseTime, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Check

    def __init__(self, unique_identifier=None, usage_limits_count=None, cryptographic_usage_mask=None, lease_time=None):
        self.unique_identifier = unique_identifier
        self.usage_limits_count = usage_limits_count
        self.cryptographic_usage_mask = cryptographic_usage_mask
        self.lease_time = lease_time
        super(CheckResponsePayload, self).__init__()


class CheckSEApplicationPortAvailableRequestPayload(RequestPayload):
    """
    CheckSEAppPortAvailableRequestPayload is the payload of a Check SE
    Application Port Available Request message.
    
    Args:
        external_port_list (list(int)): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("external_port_list", enums.Tag.ExternalPort, MULTI, REQUIRED)
    ]
    OPERATION = enums.Operation.CheckSEApplicationPortAvailable

    def __init__(self, external_port_list=None):
        self.external_port_list = external_port_list
        super(CheckSEApplicationPortAvailableRequestPayload, self).__init__()


class CheckSEApplicationPortAvailableResponsePayload(ResponsePayload):
    """
    CheckSEAppPortAvailableResponsePayload is the payload of a Check SE
    Application Port Available Response message
    
    Args:
        external_port_list (list(int)): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("external_port_list", enums.Tag.ExternalPort, MULTI, REQUIRED)
    ]
    OPERATION = enums.Operation.CheckSEApplicationPortAvailable

    def __init__(self, external_port_list=None):
        self.external_port_list = external_port_list
        super(CheckSEApplicationPortAvailableResponsePayload, self).__init__()


class ClearSEApplicationDirectoryRequestPayload(RequestPayload):
    """
    ClearSEAppDirectoryRequestPayload is the payload of a Clear SE Application
    Directory Operation Request message.
    
    Args:
        unique_identifier (str): required
        clear_home_directory (bool): required
        clear_var_directory (bool): required
        clear_tmp_directory (bool): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("clear_home_directory", enums.Tag.ClearHomeDirectory, SINGLE, REQUIRED),
        ("clear_var_directory", enums.Tag.ClearVarDirectory, SINGLE, REQUIRED),
        ("clear_tmp_directory", enums.Tag.ClearTmpDirectory, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ClearSEApplicationDirectory

    def __init__(self, unique_identifier=None, clear_home_directory=None, clear_var_directory=None, clear_tmp_directory=None):
        self.unique_identifier = unique_identifier
        self.clear_home_directory = clear_home_directory
        self.clear_var_directory = clear_var_directory
        self.clear_tmp_directory = clear_tmp_directory
        super(ClearSEApplicationDirectoryRequestPayload, self).__init__()


class ClearSEApplicationDirectoryResponsePayload(ResponsePayload):
    """
    ClearSEAppDirectoryResponsePayload is the payload of a Delete SE Application
    Directory Operation Response message.
    
    Args:
        unique_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ClearSEApplicationDirectory

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(ClearSEApplicationDirectoryResponsePayload, self).__init__()


class ConfigureNetworkRequestPayload(RequestPayload):
    """
    ConfigureNetworkRequestPayload is the payload of a Config Network Operation Request message.
    
    Args:
        restart (bool): required
        lan_interface (enums.LanInterface): required
        lan_ip (str): required
        lan_mask (str): required
        lan_gateway (str): optional
        lan_dns_list (list(str)): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("restart", enums.Tag.Restart, SINGLE, REQUIRED),
        ("lan_interface", enums.Tag.LanInterface, SINGLE, REQUIRED),
        ("lan_ip", enums.Tag.LanIP, SINGLE, REQUIRED),
        ("lan_mask", enums.Tag.LanMask, SINGLE, REQUIRED),
        ("lan_gateway", enums.Tag.LanGateway, SINGLE, OPTIONAL),
        ("lan_dns_list", enums.Tag.LanDNS, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.ConfigureNetwork

    def __init__(self, restart=None, lan_interface=None, lan_ip=None, lan_mask=None, lan_gateway=None, lan_dns_list=None):
        self.restart = restart
        self.lan_interface = lan_interface
        self.lan_ip = lan_ip
        self.lan_mask = lan_mask
        self.lan_gateway = lan_gateway
        self.lan_dns_list = lan_dns_list
        super(ConfigureNetworkRequestPayload, self).__init__()


class ConfigureNetworkResponsePayload(ResponsePayload):
    """
    ConfigureNetworkResponsePayload is the payload of a Config Network Operation Response message.
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.ConfigureNetwork

    def __init__(self):
        super(ConfigureNetworkResponsePayload, self).__init__()


class CreateKeyPairRequestPayload(RequestPayload):
    """
    CreateKeyPairRequestPayload is the payload content of a CreateKeyPair
    Operation Request.
    
    Args:
        common_template_attribute (types.CommonTemplateAttribute): optional
        private_key_template_attribute (types.PrivateKeyTemplateAttribute): optional
        public_key_template_attribute (types.PublicKeyTemplateAttribute): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("common_template_attribute", enums.Tag.CommonTemplateAttribute, SINGLE, OPTIONAL),
        ("private_key_template_attribute", enums.Tag.PrivateKeyTemplateAttribute, SINGLE, OPTIONAL),
        ("public_key_template_attribute", enums.Tag.PublicKeyTemplateAttribute, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.CreateKeyPair

    def __init__(self, common_template_attribute=None, private_key_template_attribute=None, public_key_template_attribute=None):
        self.common_template_attribute = common_template_attribute
        self.private_key_template_attribute = private_key_template_attribute
        self.public_key_template_attribute = public_key_template_attribute
        super(CreateKeyPairRequestPayload, self).__init__()


class CreateKeyPairResponsePayload(ResponsePayload):
    """
    CreateKeyPairResponsePayload is the payload content of a CreateKeyPair
    Operation Response.
    
    Args:
        private_key_unique_identifier (str): required
        public_key_unique_identifier (str): required
        private_key_template_attribute (types.PrivateKeyTemplateAttribute): optional
        public_key_template_attribute (types.PublicKeyTemplateAttribute): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("private_key_unique_identifier", enums.Tag.PrivateKeyUniqueIdentifier, SINGLE, REQUIRED),
        ("public_key_unique_identifier", enums.Tag.PublicKeyUniqueIdentifier, SINGLE, REQUIRED),
        ("private_key_template_attribute", enums.Tag.PrivateKeyTemplateAttribute, SINGLE, OPTIONAL),
        ("public_key_template_attribute", enums.Tag.PublicKeyTemplateAttribute, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.CreateKeyPair

    def __init__(self, private_key_unique_identifier=None, public_key_unique_identifier=None, private_key_template_attribute=None, public_key_template_attribute=None):
        self.private_key_unique_identifier = private_key_unique_identifier
        self.public_key_unique_identifier = public_key_unique_identifier
        self.private_key_template_attribute = private_key_template_attribute
        self.public_key_template_attribute = public_key_template_attribute
        super(CreateKeyPairResponsePayload, self).__init__()


class CreateRequestPayload(RequestPayload):
    """
    CreateRequestPayload is the payload content of a Create Operation Request
    
    Args:
        object_type (enums.ObjectType): required
        template_attribute (types.TemplateAttribute): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("object_type", enums.Tag.ObjectType, SINGLE, REQUIRED),
        ("template_attribute", enums.Tag.TemplateAttribute, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.Create

    def __init__(self, object_type=None, template_attribute=None):
        self.object_type = object_type
        self.template_attribute = template_attribute
        super(CreateRequestPayload, self).__init__()


class CreateResponsePayload(ResponsePayload):
    """
    CreateResponsePayload is the payload content of a Create Operation Response
    
    Args:
        object_type (enums.ObjectType): required
        unique_identifier (str): required
        template_attribute (types.TemplateAttribute): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("object_type", enums.Tag.ObjectType, SINGLE, REQUIRED),
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("template_attribute", enums.Tag.TemplateAttribute, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Create

    def __init__(self, object_type=None, unique_identifier=None, template_attribute=None):
        self.object_type = object_type
        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute
        super(CreateResponsePayload, self).__init__()


class CreateUserRequestPayload(RequestPayload):
    """
    CreateUserRequestPayload is the payload content of a CreateUser
    Operation Request.
    
    Args:
        user_name (str): required
        user_type (enums.UserType): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("user_name", enums.Tag.UserName, SINGLE, REQUIRED),
        ("user_type", enums.Tag.UserType, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.CreateUser

    def __init__(self, user_name=None, user_type=None):
        self.user_name = user_name
        self.user_type = user_type
        super(CreateUserRequestPayload, self).__init__()


class CreateUserResponsePayload(ResponsePayload):
    """
    CreateUserResponsePayload is the payload content of a CreateUser
    Operation Response.
    
    Args:
        pin (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("pin", enums.Tag.PIN, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.CreateUser

    def __init__(self, pin=None):
        self.pin = pin
        super(CreateUserResponsePayload, self).__init__()


class CreateVirtualHSMRequestPayload(RequestPayload):
    """
    CreateVirtualHSMRequestPayload is the payload content of a CreateVirtualHSM
    Operation Request.
    
    Args:
        vhsm_name (str): required
        ttlv_port (int): required
        https_port (int): required
        vco_name (str): required
        vhsm_options (types.VHSMOptions): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("vhsm_name", enums.Tag.VHSMName, SINGLE, REQUIRED),
        ("ttlv_port", enums.Tag.TTLVPort, SINGLE, REQUIRED),
        ("https_port", enums.Tag.HTTPSPort, SINGLE, REQUIRED),
        ("vco_name", enums.Tag.VCOName, SINGLE, REQUIRED),
        ("vhsm_options", enums.Tag.VHSMOptions, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.CreateVirtualHSM

    def __init__(self, vhsm_name=None, ttlv_port=None, https_port=None, vco_name=None, vhsm_options=None):
        self.vhsm_name = vhsm_name
        self.ttlv_port = ttlv_port
        self.https_port = https_port
        self.vco_name = vco_name
        self.vhsm_options = vhsm_options
        super(CreateVirtualHSMRequestPayload, self).__init__()


class CreateVirtualHSMResponsePayload(ResponsePayload):
    """
    CreateVirtualHSMResponsePayload is the payload content of a CreateVirtualHSM
    Operation Response.
    
    Args:
        vhsm_unique_id (int): required
        certificate (types.Certificate): required
        vco_pin (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, REQUIRED),
        ("certificate", enums.Tag.Certificate, SINGLE, REQUIRED),
        ("vco_pin", enums.Tag.VCOPin, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.CreateVirtualHSM

    def __init__(self, vhsm_unique_id=None, certificate=None, vco_pin=None):
        self.vhsm_unique_id = vhsm_unique_id
        self.certificate = certificate
        self.vco_pin = vco_pin
        super(CreateVirtualHSMResponsePayload, self).__init__()


class Credential(KmipObject):
    """
    Credential is a structure used for client identification purposes
    
    Args:
        credential_type (enums.CredentialType): required
        credential_value (types.AttestationCredential, types.DeviceCredential, types.PasswordCredential): optional
    """

    TAG = enums.Tag.Credential
    FIELDS = [
        ("credential_type", enums.Tag.CredentialType, SINGLE, REQUIRED),
        ("credential_value", enums.Tag.CredentialValue, SINGLE, MAYBE_REQUIRED)
    ]

    def __init__(self, credential_type=None, credential_value=None):
        self.credential_type = credential_type
        self.credential_value = credential_value
        super(Credential, self).__init__()


class CryptographicDomainParameters(AttributeValue):
    """
    CryptographicDomainParameters is a structure that contains a set of OPTIONAL
    fields that MAY need to be specified in the Create Key Pair Request Payload.
    
    Args:
        qlength (int): optional
        recommended_curve (enums.RecommendedCurve): optional
    """

    TAG = enums.Tag.CryptographicDomainParameters
    FIELDS = [
        ("qlength", enums.Tag.Qlength, SINGLE, OPTIONAL),
        ("recommended_curve", enums.Tag.RecommendedCurve, SINGLE, OPTIONAL)
    ]

    def __init__(self, qlength=None, recommended_curve=None):
        self.qlength = qlength
        self.recommended_curve = recommended_curve
        super(CryptographicDomainParameters, self).__init__()


class CryptographicParameters(AttributeValue):
    """
    CryptographicParameters is a structure that contains a set of OPTIONAL
    fields that describe certain cryptographic parameters to be used when
    performing cryptographic operations using the object. It is defined in section
    
    Args:
        block_cipher_mode (enums.BlockCipherMode): optional
        padding_method (enums.PaddingMethod): optional
        hashing_algorithm (enums.HashingAlgorithm): optional
        key_role_type (enums.KeyRoleType): optional
        digital_signature_algorithm (enums.DigitalSignatureAlgorithm): optional
        cryptographic_algorithm (enums.CryptographicAlgorithm): optional
        random_iv (bool): optional
        iv_length (int): optional
        tag_length (int): optional
        fixed_field_length (int): optional
        invocation_field_length (int): optional
        counter_length (int): optional
        initial_counter_value (int): optional
        mask_generator (enums.MaskGenerator): optional
        mask_generator_hashing_algorithm: optional
        p_source (bytes): optional
        salt_length (int): optional
    """

    TAG = enums.Tag.CryptographicParameters
    FIELDS = [
        ("block_cipher_mode", enums.Tag.BlockCipherMode, SINGLE, OPTIONAL),
        ("padding_method", enums.Tag.PaddingMethod, SINGLE, OPTIONAL),
        ("hashing_algorithm", enums.Tag.HashingAlgorithm, SINGLE, OPTIONAL),
        ("key_role_type", enums.Tag.KeyRoleType, SINGLE, OPTIONAL),
        ("digital_signature_algorithm", enums.Tag.DigitalSignatureAlgorithm, SINGLE, OPTIONAL),
        ("cryptographic_algorithm", enums.Tag.CryptographicAlgorithm, SINGLE, OPTIONAL),
        ("random_iv", enums.Tag.RandomIV, SINGLE, OPTIONAL),
        ("iv_length", enums.Tag.IVLength, SINGLE, OPTIONAL),
        ("tag_length", enums.Tag.TagLength, SINGLE, OPTIONAL),
        ("fixed_field_length", enums.Tag.FixedFieldLength, SINGLE, OPTIONAL),
        ("invocation_field_length", enums.Tag.InvocationFieldLength, SINGLE, OPTIONAL),
        ("counter_length", enums.Tag.CounterLength, SINGLE, OPTIONAL),
        ("initial_counter_value", enums.Tag.InitialCounterValue, SINGLE, OPTIONAL),
        ("mask_generator", enums.Tag.MaskGenerator, SINGLE, OPTIONAL),
        ("mask_generator_hashing_algorithm", enums.Tag.MaskGeneratorHashingAlgorithm, SINGLE, OPTIONAL),
        ("p_source", enums.Tag.PSource, SINGLE, OPTIONAL),
        ("salt_length", enums.Tag.SaltLength, SINGLE, OPTIONAL)
    ]

    def __init__(self, block_cipher_mode=None, padding_method=None, hashing_algorithm=None, key_role_type=None, digital_signature_algorithm=None, cryptographic_algorithm=None, random_iv=None, iv_length=None, tag_length=None, fixed_field_length=None, invocation_field_length=None, counter_length=None, initial_counter_value=None, mask_generator=None, mask_generator_hashing_algorithm=None, p_source=None, salt_length=None):
        self.block_cipher_mode = block_cipher_mode
        self.padding_method = padding_method
        self.hashing_algorithm = hashing_algorithm
        self.key_role_type = key_role_type
        self.digital_signature_algorithm = digital_signature_algorithm
        self.cryptographic_algorithm = cryptographic_algorithm
        self.random_iv = random_iv
        self.iv_length = iv_length
        self.tag_length = tag_length
        self.fixed_field_length = fixed_field_length
        self.invocation_field_length = invocation_field_length
        self.counter_length = counter_length
        self.initial_counter_value = initial_counter_value
        self.mask_generator = mask_generator
        self.mask_generator_hashing_algorithm = mask_generator_hashing_algorithm
        self.p_source = p_source
        self.salt_length = salt_length
        super(CryptographicParameters, self).__init__()


class DataPath(KmipObject):
    """
    Data path holds the path to the requested data containing the source directory and the relative path to file.
    
    Args:
        source_dir (enums.SourceDir): required
        relative_path (str): required
    """

    TAG = enums.Tag.DataPath
    FIELDS = [
        ("source_dir", enums.Tag.SourceDir, SINGLE, REQUIRED),
        ("relative_path", enums.Tag.RelativePath, SINGLE, REQUIRED)
    ]

    def __init__(self, source_dir=None, relative_path=None):
        self.source_dir = source_dir
        self.relative_path = relative_path
        super(DataPath, self).__init__()


class DeactivateVirtualHSMRequestPayload(RequestPayload):
    """
    DeactivateVirtualHSMRequestPayload is the payload of a Deactivate VHSM Operation
    Request message.
    
    Args:
        vhsm_unique_id (int): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.DeactivateVirtualHSM

    def __init__(self, vhsm_unique_id=None):
        self.vhsm_unique_id = vhsm_unique_id
        super(DeactivateVirtualHSMRequestPayload, self).__init__()


class DeactivateVirtualHSMResponsePayload(ResponsePayload):
    """
    DeactivateVirtualHSMResponsePayload is the payload of an Deactivate VHSM Operation
    Response message.
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.DeactivateVirtualHSM

    def __init__(self):
        super(DeactivateVirtualHSMResponsePayload, self).__init__()


class DecryptRequestPayload(RequestPayload):
    """
    DecryptRequestPayload is the payload of a Decrypt Operation Request message.
    This operation requests the server to perform an encryption operation on the
    provided data using a Managed Cryptographic Object as the key for the
    encryption operation.
    
    Args:
        unique_identifier (str): optional
        cryptographic_parameters (types.CryptographicParameters): optional
        data (bytes): optional
        iv_counter_nonce (bytes): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
        authenticated_encryption_additional_data (bytes): optional
        authenticated_encryption_tag (bytes): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, OPTIONAL),
        ("data", enums.Tag.Data, SINGLE, MAYBE_REQUIRED),
        ("iv_counter_nonce", enums.Tag.IVCounterNonce, SINGLE, OPTIONAL),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL),
        ("authenticated_encryption_additional_data", enums.Tag.AuthenticatedEncryptionAdditionalData, SINGLE, OPTIONAL),
        ("authenticated_encryption_tag", enums.Tag.AuthenticatedEncryptionTag, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Decrypt

    def __init__(self, unique_identifier=None, cryptographic_parameters=None, data=None, iv_counter_nonce=None, correlation_value=None, init_indicator=None, final_indicator=None, authenticated_encryption_additional_data=None, authenticated_encryption_tag=None):
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.iv_counter_nonce = iv_counter_nonce
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        self.authenticated_encryption_additional_data = authenticated_encryption_additional_data
        self.authenticated_encryption_tag = authenticated_encryption_tag
        super(DecryptRequestPayload, self).__init__()


class DecryptResponsePayload(ResponsePayload):
    """
    DecryptResponsePayload is the payload of a Decrypt Operation Response message
    
    Args:
        unique_identifier (str): required
        data (bytes): optional
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("data", enums.Tag.Data, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Decrypt

    def __init__(self, unique_identifier=None, data=None, correlation_value=None):
        self.unique_identifier = unique_identifier
        self.data = data
        self.correlation_value = correlation_value
        super(DecryptResponsePayload, self).__init__()


class DeleteAttributeRequestPayload(RequestPayload):
    """
    DeleteAttributeRequestPayload is the payload of a Delete Attribute Operation
    Request message
    
    Args:
        unique_identifier (str): optional
        attribute_name (str): required
        attribute_index (int): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("attribute_name", enums.Tag.AttributeName, SINGLE, REQUIRED),
        ("attribute_index", enums.Tag.AttributeIndex, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.DeleteAttribute

    def __init__(self, unique_identifier=None, attribute_name=None, attribute_index=None):
        self.unique_identifier = unique_identifier
        self.attribute_name = attribute_name
        self.attribute_index = attribute_index
        super(DeleteAttributeRequestPayload, self).__init__()


class DeleteAttributeResponsePayload(ResponsePayload):
    """
    DeleteAttributeResponsePayload is the payload of a Delete Attribute Operation
    Response message
    
    Args:
        unique_identifier (str): required
        attribute (types.Attribute): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("attribute", enums.Tag.Attribute, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.DeleteAttribute

    def __init__(self, unique_identifier=None, attribute=None):
        self.unique_identifier = unique_identifier
        self.attribute = attribute
        super(DeleteAttributeResponsePayload, self).__init__()


class DeleteSEApplicationRequestPayload(RequestPayload):
    """
    DeleteSEAppRequestPayload is the payload of a Delete SE Application Operation
    Request message.
    
    Args:
        unique_identifier (str): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.DeleteSEApplication

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(DeleteSEApplicationRequestPayload, self).__init__()


class DeleteSEApplicationResponsePayload(ResponsePayload):
    """
    DeleteSEAppResponsePayload is the payload of a Delete SE Application Operation
    Response message
    
    Args:
        unique_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.DeleteSEApplication

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(DeleteSEApplicationResponsePayload, self).__init__()


class DeleteUserRequestPayload(RequestPayload):
    """
    DeleteUserRequestPayload is the payload of a Delete User Operation
    Request message
    
    Args:
        username (str): required
        user_type (enums.UserType): required
        vhsm_unique_id (int): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("username", enums.Tag.Username, SINGLE, REQUIRED),
        ("user_type", enums.Tag.UserType, SINGLE, REQUIRED),
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, MAYBE_REQUIRED)
    ]
    OPERATION = enums.Operation.DeleteUser

    def __init__(self, username=None, user_type=None, vhsm_unique_id=None):
        self.username = username
        self.user_type = user_type
        self.vhsm_unique_id = vhsm_unique_id
        super(DeleteUserRequestPayload, self).__init__()


class DeleteUserResponsePayload(ResponsePayload):
    """
    DeleteUserResponsePayload is the payload of an Delete User Operation
    Response message.
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.DeleteUser

    def __init__(self):
        super(DeleteUserResponsePayload, self).__init__()


class DeleteVirtualHSMRequestPayload(RequestPayload):
    """
    DeleteVirtualHSMRequestPayload is the payload of a Delete VHSM Operation
    Request message.
    
    Args:
        vhsm_unique_id (int): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.DeleteVirtualHSM

    def __init__(self, vhsm_unique_id=None):
        self.vhsm_unique_id = vhsm_unique_id
        super(DeleteVirtualHSMRequestPayload, self).__init__()


class DeleteVirtualHSMResponsePayload(ResponsePayload):
    """
    DeleteVirtualHSMResponsePayload is the payload of an Delete VHSM Operation
    Response message.
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.DeleteVirtualHSM

    def __init__(self):
        super(DeleteVirtualHSMResponsePayload, self).__init__()


class DestroyRequestPayload(RequestPayload):
    """
    DestroyRequestPayload is the payload of a Destroy Operation Request message.
    The Destroy operation SHOULD enforce special authentication and authorization
    Only the object owner or an authorized security officer SHOULD be allowed to
    issue this request.
    Cryptographic Objects MAY only be destroyed if they are in either Pre-Active
    or Deactivated state.
    
    Args:
        unique_identifier (str): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Destroy

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(DestroyRequestPayload, self).__init__()


class DestroyResponsePayload(ResponsePayload):
    """
    DestroyResponsePayload is the payload of a Destroy Operation Response message
    
    Args:
        unique_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.Destroy

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(DestroyResponsePayload, self).__init__()


class DeviceCredential(KmipObject):
    """
    DeviceCredential is the defined type for the value of Credential when
    the CredentialType is Device
    
    Args:
        device_serial_number (str): optional
        password (str): optional
        device_identifier (str): optional
        network_identifier (str): optional
        machine_identifier (str): optional
        media_identifier (str): optional
    """

    TAG = enums.Tag.CredentialValue
    FIELDS = [
        ("device_serial_number", enums.Tag.DeviceSerialNumber, SINGLE, OPTIONAL),
        ("password", enums.Tag.Password, SINGLE, OPTIONAL),
        ("device_identifier", enums.Tag.DeviceIdentifier, SINGLE, OPTIONAL),
        ("network_identifier", enums.Tag.NetworkIdentifier, SINGLE, OPTIONAL),
        ("machine_identifier", enums.Tag.MachineIdentifier, SINGLE, OPTIONAL),
        ("media_identifier", enums.Tag.MediaIdentifier, SINGLE, OPTIONAL)
    ]

    def __init__(self, device_serial_number=None, password=None, device_identifier=None, network_identifier=None, machine_identifier=None, media_identifier=None):
        self.device_serial_number = device_serial_number
        self.password = password
        self.device_identifier = device_identifier
        self.network_identifier = network_identifier
        self.machine_identifier = machine_identifier
        self.media_identifier = media_identifier
        super(DeviceCredential, self).__init__()


class DeviceStatus(KmipObject):
    """
    DeviceStatus holds information about of the status of the device.
    
    Args:
        temperature (int): required
        battery_voltage (int): required
        monitor_state (enums.MonitorState): required
        intrusion_state (enums.IntrusionState): required
        knet_state (enums.KNETState): required
        fips_active_mode (bool): required
    """

    TAG = enums.Tag.DeviceStatus
    FIELDS = [
        ("temperature", enums.Tag.Temperature, SINGLE, REQUIRED),
        ("battery_voltage", enums.Tag.BatteryVoltage, SINGLE, REQUIRED),
        ("monitor_state", enums.Tag.MonitorState, SINGLE, REQUIRED),
        ("intrusion_state", enums.Tag.IntrusionState, SINGLE, REQUIRED),
        ("knet_state", enums.Tag.KNETState, SINGLE, REQUIRED),
        ("fips_active_mode", enums.Tag.FIPSActiveMode, SINGLE, REQUIRED)
    ]

    def __init__(self, temperature=None, battery_voltage=None, monitor_state=None, intrusion_state=None, knet_state=None, fips_active_mode=None):
        self.temperature = temperature
        self.battery_voltage = battery_voltage
        self.monitor_state = monitor_state
        self.intrusion_state = intrusion_state
        self.knet_state = knet_state
        self.fips_active_mode = fips_active_mode
        super(DeviceStatus, self).__init__()


class Digest(AttributeValue):
    """
    Digest attribute is a structure that contains the digest value of the key
    or secret data, certificate, or opaque object.
    
    Args:
        hashing_algorithm (enums.HashingAlgorithm): required
        digest_value (bytes): optional
        key_format_type (enums.KeyFormatType): optional
    """

    TAG = enums.Tag.Digest
    FIELDS = [
        ("hashing_algorithm", enums.Tag.HashingAlgorithm, SINGLE, REQUIRED),
        ("digest_value", enums.Tag.DigestValue, SINGLE, MAYBE_REQUIRED),
        ("key_format_type", enums.Tag.KeyFormatType, SINGLE, MAYBE_REQUIRED)
    ]

    def __init__(self, hashing_algorithm=None, digest_value=None, key_format_type=None):
        self.hashing_algorithm = hashing_algorithm
        self.digest_value = digest_value
        self.key_format_type = key_format_type
        super(Digest, self).__init__()


class DiscoverVersionsRequestPayload(RequestPayload):
    """
    DiscoverVersionsRequestPayload is the payload of a DiscoverVersions
    Operation Request message. The DiscoverVersions operation is used by the
    client to determine a list of protocol versions that is supported by the
    server. The Request Payload contains an OPTIONAL list of protocol versions
    that is supported by the client. The protocol versions SHALL be ranked in
    decreasing order of preference.
    
    Args:
        protocol_version_list (list(types.ProtocolVersion)): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("protocol_version_list", enums.Tag.ProtocolVersion, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.DiscoverVersions

    def __init__(self, protocol_version_list=None):
        self.protocol_version_list = protocol_version_list
        super(DiscoverVersionsRequestPayload, self).__init__()


class DiscoverVersionsResponsePayload(ResponsePayload):
    """
    DiscoverVersionsResponsePayload is the payload of a DiscoverVersions
    Operation Response message
    
    Args:
        protocol_version_list (list(types.ProtocolVersion)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("protocol_version_list", enums.Tag.ProtocolVersion, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.DiscoverVersions

    def __init__(self, protocol_version_list=None):
        self.protocol_version_list = protocol_version_list
        super(DiscoverVersionsResponsePayload, self).__init__()


class EditVirtualHSMRequestPayload(RequestPayload):
    """
    EditVirtualHSMRequestPayload is the payload content of a CreateVirtualHSM
    Operation Request.
    
    Args:
        vhsm_unique_id (int): required
        ttlv_port (int): optional
        https_port (int): optional
        vhsm_options (types.VHSMOptions): optional
        remove_vhsm_port_range (bool): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, REQUIRED),
        ("ttlv_port", enums.Tag.TTLVPort, SINGLE, OPTIONAL),
        ("https_port", enums.Tag.HTTPSPort, SINGLE, OPTIONAL),
        ("vhsm_options", enums.Tag.VHSMOptions, SINGLE, OPTIONAL),
        ("remove_vhsm_port_range", enums.Tag.RemoveVHSMPortRange, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.EditVirtualHSM

    def __init__(self, vhsm_unique_id=None, ttlv_port=None, https_port=None, vhsm_options=None, remove_vhsm_port_range=None):
        self.vhsm_unique_id = vhsm_unique_id
        self.ttlv_port = ttlv_port
        self.https_port = https_port
        self.vhsm_options = vhsm_options
        self.remove_vhsm_port_range = remove_vhsm_port_range
        super(EditVirtualHSMRequestPayload, self).__init__()


class EditVirtualHSMResponsePayload(ResponsePayload):
    """
    EditVirtualHSMResponsePayload is the payload content of a CreateVirtualHSM
    Operation Response.
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.EditVirtualHSM

    def __init__(self):
        super(EditVirtualHSMResponsePayload, self).__init__()


class EncryptRequestPayload(RequestPayload):
    """
    EncryptRequestPayload is the payload of a Encrypt Operation Request message.
    This operation requests the server to perform an encryption operation on the
    provided data using a Managed Cryptographic Object as the key for the
    encryption operation.
    
    Args:
        unique_identifier (str): optional
        cryptographic_parameters (types.CryptographicParameters): optional
        data (bytes): required
        iv_counter_nonce (bytes): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
        authenticated_encryption_additional_data (bytes): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, OPTIONAL),
        ("data", enums.Tag.Data, SINGLE, REQUIRED),
        ("iv_counter_nonce", enums.Tag.IVCounterNonce, SINGLE, OPTIONAL),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL),
        ("authenticated_encryption_additional_data", enums.Tag.AuthenticatedEncryptionAdditionalData, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Encrypt

    def __init__(self, unique_identifier=None, cryptographic_parameters=None, data=None, iv_counter_nonce=None, correlation_value=None, init_indicator=None, final_indicator=None, authenticated_encryption_additional_data=None):
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.iv_counter_nonce = iv_counter_nonce
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        self.authenticated_encryption_additional_data = authenticated_encryption_additional_data
        super(EncryptRequestPayload, self).__init__()


class EncryptResponsePayload(ResponsePayload):
    """
    EncryptResponsePayload is the payload of a Encrypt Operation Response message
    
    Args:
        unique_identifier (str): required
        data (bytes): required
        iv_counter_nonce (bytes): optional
        correlation_value (bytes): optional
        authenticated_encryption_tag (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("data", enums.Tag.Data, SINGLE, REQUIRED),
        ("iv_counter_nonce", enums.Tag.IVCounterNonce, SINGLE, OPTIONAL),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("authenticated_encryption_tag", enums.Tag.AuthenticatedEncryptionTag, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Encrypt

    def __init__(self, unique_identifier=None, data=None, iv_counter_nonce=None, correlation_value=None, authenticated_encryption_tag=None):
        self.unique_identifier = unique_identifier
        self.data = data
        self.iv_counter_nonce = iv_counter_nonce
        self.correlation_value = correlation_value
        self.authenticated_encryption_tag = authenticated_encryption_tag
        super(EncryptResponsePayload, self).__init__()


class EncryptionKeyInformation(KmipObject):
    """
    EncryptionKeyInformation describes the key used for encryption
    
    Args:
        unique_identifier (str): required
        cryptographic_parameters (types.CryptographicParameters): optional
    """

    TAG = enums.Tag.EncryptionKeyInformation
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, OPTIONAL)
    ]

    def __init__(self, unique_identifier=None, cryptographic_parameters=None):
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        super(EncryptionKeyInformation, self).__init__()


class ExportPhysicalHSMRequestPayload(RequestPayload):
    """
    ExportPhysicalHSMRequestPayload is the payload of a Get SE
    Data Operation Request message.
    
    Args:
        certificate_list (list(types.Certificate)): optional
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("certificate_list", enums.Tag.Certificate, MULTI, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, MAYBE_REQUIRED)
    ]
    OPERATION = enums.Operation.ExportPhysicalHSM

    def __init__(self, certificate_list=None, correlation_value=None):
        self.certificate_list = certificate_list
        self.correlation_value = correlation_value
        super(ExportPhysicalHSMRequestPayload, self).__init__()


class ExportPhysicalHSMResponsePayload(ResponsePayload):
    """
    ExportPhysicalHSMResponsePayload is the payload of a Get SE
    Data Operation Response message
    
    Args:
        data (bytes): required
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("data", enums.Tag.Data, SINGLE, REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, MAYBE_REQUIRED)
    ]
    OPERATION = enums.Operation.ExportPhysicalHSM

    def __init__(self, data=None, correlation_value=None):
        self.data = data
        self.correlation_value = correlation_value
        super(ExportPhysicalHSMResponsePayload, self).__init__()


class ExportVirtualHSMRequestPayload(RequestPayload):
    """
    ExportVirtualHSMRequestPayload is the payload of a Get SE
    Data Operation Request message.
    
    Args:
        vhsm_unique_id (int): optional
        certificate_list (list(types.Certificate)): optional
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, MAYBE_REQUIRED),
        ("certificate_list", enums.Tag.Certificate, MULTI, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, MAYBE_REQUIRED)
    ]
    OPERATION = enums.Operation.ExportVirtualHSM

    def __init__(self, vhsm_unique_id=None, certificate_list=None, correlation_value=None):
        self.vhsm_unique_id = vhsm_unique_id
        self.certificate_list = certificate_list
        self.correlation_value = correlation_value
        super(ExportVirtualHSMRequestPayload, self).__init__()


class ExportVirtualHSMResponsePayload(ResponsePayload):
    """
    ExportVirtualHSMResponsePayload is the payload of a Get SE
    Data Operation Response message
    
    Args:
        vhsm_unique_id (int): required
        correlation_value (bytes): optional
        data (bytes): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, MAYBE_REQUIRED),
        ("data", enums.Tag.Data, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ExportVirtualHSM

    def __init__(self, vhsm_unique_id=None, correlation_value=None, data=None):
        self.vhsm_unique_id = vhsm_unique_id
        self.correlation_value = correlation_value
        self.data = data
        super(ExportVirtualHSMResponsePayload, self).__init__()


class ExtensionInformation(KmipObject):
    """
    Extension Information object is a structure describing Objects with Item Tag
    values in the Extensions range
    
    Args:
        extension_name (str): required
        extension_tag (int): optional
        extension_type (int): optional
    """

    TAG = enums.Tag.ExtensionInformation
    FIELDS = [
        ("extension_name", enums.Tag.ExtensionName, SINGLE, REQUIRED),
        ("extension_tag", enums.Tag.ExtensionTag, SINGLE, OPTIONAL),
        ("extension_type", enums.Tag.ExtensionType, SINGLE, OPTIONAL)
    ]

    def __init__(self, extension_name=None, extension_tag=None, extension_type=None):
        self.extension_name = extension_name
        self.extension_tag = extension_tag
        self.extension_type = extension_type
        super(ExtensionInformation, self).__init__()


class FirmwareUpdateRequestPayload(RequestPayload):
    """
    FirmwareUpdateRequestPayload is the payload of a Firmware Update Operation Request message.
    
    Args:
        data (bytes): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("data", enums.Tag.Data, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.FirmwareUpdate

    def __init__(self, data=None, correlation_value=None, init_indicator=None, final_indicator=None):
        self.data = data
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        super(FirmwareUpdateRequestPayload, self).__init__()


class FirmwareUpdateResponsePayload(ResponsePayload):
    """
    FirmwareUpdateResponsePayload holds the information of a Firmware Update Operation
    Response Payload.
    
    Args:
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.FirmwareUpdate

    def __init__(self, correlation_value=None):
        self.correlation_value = correlation_value
        super(FirmwareUpdateResponsePayload, self).__init__()


class GetAttributeListRequestPayload(RequestPayload):
    """
    GetAttributeListRequestPayload is the payload of a Get Attribute List
    Operation Request message
    
    Args:
        unique_identifier (str): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetAttributeList

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(GetAttributeListRequestPayload, self).__init__()


class GetAttributeListResponsePayload(ResponsePayload):
    """
    GetAttributeListResponsePayload is the payload of a Get Attribute List
    Operation Response message
    
    Args:
        unique_identifier (str): required
        attribute_name_list (list(str)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("attribute_name_list", enums.Tag.AttributeName, MULTI, MAYBE_REQUIRED)
    ]
    OPERATION = enums.Operation.GetAttributeList

    def __init__(self, unique_identifier=None, attribute_name_list=None):
        self.unique_identifier = unique_identifier
        self.attribute_name_list = attribute_name_list
        super(GetAttributeListResponsePayload, self).__init__()


class GetAttributesRequestPayload(RequestPayload):
    """
    GetAttributesRequestPayload is the payload of a Get Attributes Operation
    Request message
    
    Args:
        unique_identifier (str): optional
        attribute_name_list (list(str)): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("attribute_name_list", enums.Tag.AttributeName, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetAttributes

    def __init__(self, unique_identifier=None, attribute_name_list=None):
        self.unique_identifier = unique_identifier
        self.attribute_name_list = attribute_name_list
        super(GetAttributesRequestPayload, self).__init__()


class GetAttributesResponsePayload(ResponsePayload):
    """
    GetAttributesResponsePayload is the payload of a Get Attributes Operation
    Response message
    
    Args:
        unique_identifier (str): required
        attribute_list (list(types.Attribute)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("attribute_list", enums.Tag.Attribute, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetAttributes

    def __init__(self, unique_identifier=None, attribute_list=None):
        self.unique_identifier = unique_identifier
        self.attribute_list = attribute_list
        super(GetAttributesResponsePayload, self).__init__()


class GetDeviceInformationRequestPayload(RequestPayload):
    """
    GetDeviceInformationRequestPayload is the payload content of a GetDeviceInformation
    Operation Request.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.GetDeviceInformation

    def __init__(self):
        super(GetDeviceInformationRequestPayload, self).__init__()


class GetDeviceInformationResponsePayload(ResponsePayload):
    """
    GetDeviceInformationResponsePayload is the payload content of a GetDeviceInformation
    Operation Response.
    
    Args:
        device_status (types.DeviceStatus): required
        version (types.Version): required
        device_serial_number (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("device_status", enums.Tag.DeviceStatus, SINGLE, REQUIRED),
        ("version", enums.Tag.Version, SINGLE, REQUIRED),
        ("device_serial_number", enums.Tag.DeviceSerialNumber, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.GetDeviceInformation

    def __init__(self, device_status=None, version=None, device_serial_number=None):
        self.device_status = device_status
        self.version = version
        self.device_serial_number = device_serial_number
        super(GetDeviceInformationResponsePayload, self).__init__()


class GetDeviceTimeRequestPayload(RequestPayload):
    """
    GetDeviceTimeRequestPayload is the payload of a Get Device Time Operation Request message.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.GetDeviceTime

    def __init__(self):
        super(GetDeviceTimeRequestPayload, self).__init__()


class GetDeviceTimeResponsePayload(ResponsePayload):
    """
    GetDeviceTimeResponsePayload is the payload of a Get Device Time Operation Response message.
    
    Args:
        year (str): required
        month (str): required
        day (str): required
        hour (str): required
        minute (str): required
        second (str): required
        timezone (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("year", enums.Tag.Year, SINGLE, REQUIRED),
        ("month", enums.Tag.Month, SINGLE, REQUIRED),
        ("day", enums.Tag.Day, SINGLE, REQUIRED),
        ("hour", enums.Tag.Hour, SINGLE, REQUIRED),
        ("minute", enums.Tag.Minute, SINGLE, REQUIRED),
        ("second", enums.Tag.Second, SINGLE, REQUIRED),
        ("timezone", enums.Tag.Timezone, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.GetDeviceTime

    def __init__(self, year=None, month=None, day=None, hour=None, minute=None, second=None, timezone=None):
        self.year = year
        self.month = month
        self.day = day
        self.hour = hour
        self.minute = minute
        self.second = second
        self.timezone = timezone
        super(GetDeviceTimeResponsePayload, self).__init__()


class GetLogLevelRequestPayload(RequestPayload):
    """
    GetLogLevelRequestPayload is the payload of a Get Log Level Operation Request message.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.GetLogLevel

    def __init__(self):
        super(GetLogLevelRequestPayload, self).__init__()


class GetLogLevelResponsePayload(ResponsePayload):
    """
    GetLogLevelResponsePayload is the payload of a Get Log Level Operation Response message.
    
    Args:
        log_level (enums.LogLevel): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("log_level", enums.Tag.LogLevel, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.GetLogLevel

    def __init__(self, log_level=None):
        self.log_level = log_level
        super(GetLogLevelResponsePayload, self).__init__()


class GetNetworkConfigurationRequestPayload(RequestPayload):
    """
    GetNetworkConfigurationRequestPayload is the payload of a Config Network Operation Request message.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.GetNetworkConfiguration

    def __init__(self):
        super(GetNetworkConfigurationRequestPayload, self).__init__()


class GetNetworkConfigurationResponsePayload(ResponsePayload):
    """
    GetNetworkConfigurationResponsePayload is the payload of a Config Network Operation Response message.
    
    Args:
        lan_interface_information_list (list(types.LanInterfaceInformation)): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("lan_interface_information_list", enums.Tag.LanInterfaceInformation, MULTI, REQUIRED)
    ]
    OPERATION = enums.Operation.GetNetworkConfiguration

    def __init__(self, lan_interface_information_list=None):
        self.lan_interface_information_list = lan_interface_information_list
        super(GetNetworkConfigurationResponsePayload, self).__init__()


class GetPHSMUsageRequestPayload(RequestPayload):
    """
    GetPHSMUsageRequestPayload is the payload content of a GetPHSMUsage
    Operation Request.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.GetPHSMUsage

    def __init__(self):
        super(GetPHSMUsageRequestPayload, self).__init__()


class GetPHSMUsageResponsePayload(ResponsePayload):
    """
    GetPHSMUsageResponsePayload is the payload content of a GetPHSMUsage
    Operation Response.
    
    Args:
        usage (types.Usage): required
        vhsm_usage_list (list(types.VHSMUsage)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("usage", enums.Tag.Usage, SINGLE, REQUIRED),
        ("vhsm_usage_list", enums.Tag.VHSMUsage, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetPHSMUsage

    def __init__(self, usage=None, vhsm_usage_list=None):
        self.usage = usage
        self.vhsm_usage_list = vhsm_usage_list
        super(GetPHSMUsageResponsePayload, self).__init__()


class GetRequestPayload(RequestPayload):
    """
    GetRequestPayload holds the information of a Get Operation Request
    Payload.
    
    Args:
        unique_identifier (str): optional
        key_format_type (enums.KeyFormatType): optional
        key_wrap_type (enums.KeyWrapType): optional
        key_compression_type (enums.KeyCompressionType): optional
        key_wrapping_specification (types.KeyWrappingSpecification): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("key_format_type", enums.Tag.KeyFormatType, SINGLE, OPTIONAL),
        ("key_wrap_type", enums.Tag.KeyWrapType, SINGLE, OPTIONAL),
        ("key_compression_type", enums.Tag.KeyCompressionType, SINGLE, OPTIONAL),
        ("key_wrapping_specification", enums.Tag.KeyWrappingSpecification, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Get

    def __init__(self, unique_identifier=None, key_format_type=None, key_wrap_type=None, key_compression_type=None, key_wrapping_specification=None):
        self.unique_identifier = unique_identifier
        self.key_format_type = key_format_type
        self.key_wrap_type = key_wrap_type
        self.key_compression_type = key_compression_type
        self.key_wrapping_specification = key_wrapping_specification
        super(GetRequestPayload, self).__init__()


class GetRequesterTypeRequestPayload(RequestPayload):
    """
    GetRequesterTypeRequestPayload is the payload content of a GetRequesterType
    Operation Request.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.GetRequesterType

    def __init__(self):
        super(GetRequesterTypeRequestPayload, self).__init__()


class GetRequesterTypeResponsePayload(ResponsePayload):
    """
    GetRequesterTypeResponsePayload is the payload content of a GetRequesterType
    Operation Response.
    
    Args:
        user_type (enums.UserType): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("user_type", enums.Tag.UserType, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.GetRequesterType

    def __init__(self, user_type=None):
        self.user_type = user_type
        super(GetRequesterTypeResponsePayload, self).__init__()


class GetResponsePayload(ResponsePayload):
    """
    GetResponsePayload holds the information of a Get Operation Response
    Payload.
    
    Args:
        object_type (enums.ObjectType): required
        unique_identifier (str): required
        object (types.Certificate, types.SymmetricKey, types.PGPKey, types.PrivateKey, types.PublicKey, types.SplitKey, types.Template, types.SecretData, types.OpaqueObject): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("object_type", enums.Tag.ObjectType, SINGLE, REQUIRED),
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("object", (enums.Tag.Certificate, enums.Tag.SymmetricKey, enums.Tag.PGPKey, enums.Tag.PrivateKey, enums.Tag.PublicKey, enums.Tag.SplitKey, enums.Tag.Template, enums.Tag.SecretData, enums.Tag.OpaqueObject,), SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.Get

    def __init__(self, object_type=None, unique_identifier=None, object=None):
        self.object_type = object_type
        self.unique_identifier = unique_identifier
        self.object = object
        super(GetResponsePayload, self).__init__()


class GetSEApplicationStateRequestPayload(RequestPayload):
    """
    GetSEAppStateRequestPayload is the payload of a Get SE
    State Operation Request message.
    
    Args:
        unique_identifier (str): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.GetSEApplicationState

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(GetSEApplicationStateRequestPayload, self).__init__()


class GetSEApplicationStateResponsePayload(ResponsePayload):
    """
    GetSEAppStateResponsePayload is the payload of a Get SE
    State Operation Response message
    
    Args:
        unique_identifier (str): required
        se_application_state (enums.SEApplicationState): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("se_application_state", enums.Tag.SEApplicationState, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.GetSEApplicationState

    def __init__(self, unique_identifier=None, se_application_state=None):
        self.unique_identifier = unique_identifier
        self.se_application_state = se_application_state
        super(GetSEApplicationStateResponsePayload, self).__init__()


class GetSEApplicationUsageRequestPayload(RequestPayload):
    """
    GetSEAppUsageRequestPayload is the payload content of a GetSEAppUsage
    Operation Request.
    
    Args:
        unique_identifier (str): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetSEApplicationUsage

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(GetSEApplicationUsageRequestPayload, self).__init__()


class GetSEApplicationUsageResponsePayload(ResponsePayload):
    """
    GetSEAppUsageResponsePayload is the payload content of a GetSEAppUsage
    Operation Response.
    
    Args:
        usage (types.Usage): required
        se_application_usage_list (list(types.SEApplicationUsage)): optional
        se_application_instance_usage_list (list(types.SEApplicationInstanceUsage)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("usage", enums.Tag.Usage, SINGLE, REQUIRED),
        ("se_application_usage_list", enums.Tag.SEApplicationUsage, MULTI, OPTIONAL),
        ("se_application_instance_usage_list", enums.Tag.SEApplicationInstanceUsage, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetSEApplicationUsage

    def __init__(self, usage=None, se_application_usage_list=None, se_application_instance_usage_list=None):
        self.usage = usage
        self.se_application_usage_list = se_application_usage_list
        self.se_application_instance_usage_list = se_application_instance_usage_list
        super(GetSEApplicationUsageResponsePayload, self).__init__()


class GetSEApplicationDataRequestPayload(RequestPayload):
    """
    GetSEApplicationDataRequestPayload is the payload of a Get SE
    Data Operation Request message.
    
    Args:
        unique_identifier (str): optional
        correlation_value (bytes): optional
        data_path_list (list(types.DataPath)): optional
        se_log_request_list (list(types.SELogRequest)): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("data_path_list", enums.Tag.DataPath, MULTI, OPTIONAL),
        ("se_log_request_list", enums.Tag.SELogRequest, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetSEApplicationData

    def __init__(self, unique_identifier=None, correlation_value=None, data_path_list=None, se_log_request_list=None):
        self.unique_identifier = unique_identifier
        self.correlation_value = correlation_value
        self.data_path_list = data_path_list
        self.se_log_request_list = se_log_request_list
        super(GetSEApplicationDataRequestPayload, self).__init__()


class GetSEApplicationDataResponsePayload(ResponsePayload):
    """
    GetSEApplicationDataResponsePayload is the payload of a Get SE
    Data Operation Response message
    
    Args:
        unique_identifier (str): required
        correlation_value (bytes): optional
        se_application_data_list (list(types.SEApplicationData)): optional
        se_log_response_list (list(types.SELogResponse)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("se_application_data_list", enums.Tag.SEApplicationData, MULTI, OPTIONAL),
        ("se_log_response_list", enums.Tag.SELogResponse, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetSEApplicationData

    def __init__(self, unique_identifier=None, correlation_value=None, se_application_data_list=None, se_log_response_list=None):
        self.unique_identifier = unique_identifier
        self.correlation_value = correlation_value
        self.se_application_data_list = se_application_data_list
        self.se_log_response_list = se_log_response_list
        super(GetSEApplicationDataResponsePayload, self).__init__()


class GetSNMPDataRequestPayload(RequestPayload):
    """
    GetSNMPDataRequestPayload is the payload content of a CreateVirtualHSM
    Operation Request.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.GetSNMPData

    def __init__(self):
        super(GetSNMPDataRequestPayload, self).__init__()


class GetSNMPDataResponsePayload(ResponsePayload):
    """
    GetSNMPDataResponsePayload is the payload content of a CreateVirtualHSM
    Operation Response.
    
    Args:
        system_description (str): required
        system_contact (str): required
        system_name (str): required
        system_location (str): required
        system_services (int): required
        knet_serial_number (str): required
        knet_firmware_version (str): required
        knet_hardware_version (str): required
        knet_model (str): required
        knet_fips_mode_enabled (bool): required
        knet_mc_t7_mode_enabled (bool): required
        knet_pci_mode_enabled (bool): required
        knet_license_id (str): required
        knet_perfomance_limit (int): required
        knet_vhsm_enabled (bool): required
        knet_vhsm_limit (int): required
        knet_secure_execution_enabled (bool): required
        knet_number_of_users (int): required
        knet_number_of_objects (int): required
        knet_total_bytes (int): required
        knet_available_bytes (int): required
        knet_allocated_bytes (int): required
        knet_busy_time (int): required
        knet_processor_usage (int): required
        knet_command_count (int): required
        knet_temperature (int): required
        knet_ip_int1 (str): required
        knet_ip_int2 (str): required
        knet_vhs_ms_created (int): required
        knet_vhs_ms_available (int): required
        knet_network1_status (str): required
        knet_network2_status (str): required
        knet_network1_bandwidth (int): required
        knet_network2_bandwidth (int): required
        knet_clients_connected (int): required
        knet_self_test_result (str): required
        knet_self_test_time (datetime.datetime): required
        knet_error_count (int): required
        knet_auth_error_count (int): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("system_description", enums.Tag.SystemDescription, SINGLE, REQUIRED),
        ("system_contact", enums.Tag.SystemContact, SINGLE, REQUIRED),
        ("system_name", enums.Tag.SystemName, SINGLE, REQUIRED),
        ("system_location", enums.Tag.SystemLocation, SINGLE, REQUIRED),
        ("system_services", enums.Tag.SystemServices, SINGLE, REQUIRED),
        ("knet_serial_number", enums.Tag.KnetSerialNumber, SINGLE, REQUIRED),
        ("knet_firmware_version", enums.Tag.KnetFirmwareVersion, SINGLE, REQUIRED),
        ("knet_hardware_version", enums.Tag.KnetHardwareVersion, SINGLE, REQUIRED),
        ("knet_model", enums.Tag.KnetModel, SINGLE, REQUIRED),
        ("knet_fips_mode_enabled", enums.Tag.KnetFIPSModeEnabled, SINGLE, REQUIRED),
        ("knet_mc_t7_mode_enabled", enums.Tag.KnetMCT7ModeEnabled, SINGLE, REQUIRED),
        ("knet_pci_mode_enabled", enums.Tag.KnetPCIModeEnabled, SINGLE, REQUIRED),
        ("knet_license_id", enums.Tag.KnetLicenseID, SINGLE, REQUIRED),
        ("knet_perfomance_limit", enums.Tag.KnetPerfomanceLimit, SINGLE, REQUIRED),
        ("knet_vhsm_enabled", enums.Tag.KnetVhsmEnabled, SINGLE, REQUIRED),
        ("knet_vhsm_limit", enums.Tag.KnetVhsmLimit, SINGLE, REQUIRED),
        ("knet_secure_execution_enabled", enums.Tag.KnetSecureExecutionEnabled, SINGLE, REQUIRED),
        ("knet_number_of_users", enums.Tag.KnetNumberOfUsers, SINGLE, REQUIRED),
        ("knet_number_of_objects", enums.Tag.KnetNumberOfObjects, SINGLE, REQUIRED),
        ("knet_total_bytes", enums.Tag.KnetTotalBytes, SINGLE, REQUIRED),
        ("knet_available_bytes", enums.Tag.KnetAvailableBytes, SINGLE, REQUIRED),
        ("knet_allocated_bytes", enums.Tag.KnetAllocatedBytes, SINGLE, REQUIRED),
        ("knet_busy_time", enums.Tag.KnetBusyTime, SINGLE, REQUIRED),
        ("knet_processor_usage", enums.Tag.KnetProcessorUsage, SINGLE, REQUIRED),
        ("knet_command_count", enums.Tag.KnetCommandCount, SINGLE, REQUIRED),
        ("knet_temperature", enums.Tag.KnetTemperature, SINGLE, REQUIRED),
        ("knet_ip_int1", enums.Tag.KnetIPInt1, SINGLE, REQUIRED),
        ("knet_ip_int2", enums.Tag.KnetIPInt2, SINGLE, REQUIRED),
        ("knet_vhs_ms_created", enums.Tag.KnetVHSMsCreated, SINGLE, REQUIRED),
        ("knet_vhs_ms_available", enums.Tag.KnetVHSMsAvailable, SINGLE, REQUIRED),
        ("knet_network1_status", enums.Tag.KnetNetwork1Status, SINGLE, REQUIRED),
        ("knet_network2_status", enums.Tag.KnetNetwork2Status, SINGLE, REQUIRED),
        ("knet_network1_bandwidth", enums.Tag.KnetNetwork1Bandwidth, SINGLE, REQUIRED),
        ("knet_network2_bandwidth", enums.Tag.KnetNetwork2Bandwidth, SINGLE, REQUIRED),
        ("knet_clients_connected", enums.Tag.KnetClientsConnected, SINGLE, REQUIRED),
        ("knet_self_test_result", enums.Tag.KnetSelfTestResult, SINGLE, REQUIRED),
        ("knet_self_test_time", enums.Tag.KnetSelfTestTime, SINGLE, REQUIRED),
        ("knet_error_count", enums.Tag.KnetErrorCount, SINGLE, REQUIRED),
        ("knet_auth_error_count", enums.Tag.KnetAuthErrorCount, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.GetSNMPData

    def __init__(self, system_description=None, system_contact=None, system_name=None, system_location=None, system_services=None, knet_serial_number=None, knet_firmware_version=None, knet_hardware_version=None, knet_model=None, knet_fips_mode_enabled=None, knet_mc_t7_mode_enabled=None, knet_pci_mode_enabled=None, knet_license_id=None, knet_perfomance_limit=None, knet_vhsm_enabled=None, knet_vhsm_limit=None, knet_secure_execution_enabled=None, knet_number_of_users=None, knet_number_of_objects=None, knet_total_bytes=None, knet_available_bytes=None, knet_allocated_bytes=None, knet_busy_time=None, knet_processor_usage=None, knet_command_count=None, knet_temperature=None, knet_ip_int1=None, knet_ip_int2=None, knet_vhs_ms_created=None, knet_vhs_ms_available=None, knet_network1_status=None, knet_network2_status=None, knet_network1_bandwidth=None, knet_network2_bandwidth=None, knet_clients_connected=None, knet_self_test_result=None, knet_self_test_time=None, knet_error_count=None, knet_auth_error_count=None):
        self.system_description = system_description
        self.system_contact = system_contact
        self.system_name = system_name
        self.system_location = system_location
        self.system_services = system_services
        self.knet_serial_number = knet_serial_number
        self.knet_firmware_version = knet_firmware_version
        self.knet_hardware_version = knet_hardware_version
        self.knet_model = knet_model
        self.knet_fips_mode_enabled = knet_fips_mode_enabled
        self.knet_mc_t7_mode_enabled = knet_mc_t7_mode_enabled
        self.knet_pci_mode_enabled = knet_pci_mode_enabled
        self.knet_license_id = knet_license_id
        self.knet_perfomance_limit = knet_perfomance_limit
        self.knet_vhsm_enabled = knet_vhsm_enabled
        self.knet_vhsm_limit = knet_vhsm_limit
        self.knet_secure_execution_enabled = knet_secure_execution_enabled
        self.knet_number_of_users = knet_number_of_users
        self.knet_number_of_objects = knet_number_of_objects
        self.knet_total_bytes = knet_total_bytes
        self.knet_available_bytes = knet_available_bytes
        self.knet_allocated_bytes = knet_allocated_bytes
        self.knet_busy_time = knet_busy_time
        self.knet_processor_usage = knet_processor_usage
        self.knet_command_count = knet_command_count
        self.knet_temperature = knet_temperature
        self.knet_ip_int1 = knet_ip_int1
        self.knet_ip_int2 = knet_ip_int2
        self.knet_vhs_ms_created = knet_vhs_ms_created
        self.knet_vhs_ms_available = knet_vhs_ms_available
        self.knet_network1_status = knet_network1_status
        self.knet_network2_status = knet_network2_status
        self.knet_network1_bandwidth = knet_network1_bandwidth
        self.knet_network2_bandwidth = knet_network2_bandwidth
        self.knet_clients_connected = knet_clients_connected
        self.knet_self_test_result = knet_self_test_result
        self.knet_self_test_time = knet_self_test_time
        self.knet_error_count = knet_error_count
        self.knet_auth_error_count = knet_auth_error_count
        super(GetSNMPDataResponsePayload, self).__init__()


class GetSystemLogRequestPayload(RequestPayload):
    """
    GetSystemLogRequestPayload is the payload of a Get SE
    Data Operation Request message.
    
    Args:
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetSystemLog

    def __init__(self, correlation_value=None):
        self.correlation_value = correlation_value
        super(GetSystemLogRequestPayload, self).__init__()


class GetSystemLogResponsePayload(ResponsePayload):
    """
    GetSystemLogResponsePayload is the payload of a Get SE
    Data Operation Response message
    
    Args:
        correlation_value (bytes): optional
        data (bytes): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("data", enums.Tag.Data, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.GetSystemLog

    def __init__(self, correlation_value=None, data=None):
        self.correlation_value = correlation_value
        self.data = data
        super(GetSystemLogResponsePayload, self).__init__()


class GetTLSCertificateRequestPayload(RequestPayload):
    """
    GetTLSCertificateRequestPayload is the payload of a Get TLS
    Certificate Operation Request message.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.GetTLSCertificate

    def __init__(self):
        super(GetTLSCertificateRequestPayload, self).__init__()


class GetTLSCertificateResponsePayload(ResponsePayload):
    """
    GetTLSCertificateResponsePayload is the payload of a Get TLS
    Certificate Operation Response message
    
    Args:
        server_certificate (bytes): required
        ca_certificate (bytes): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("server_certificate", enums.Tag.ServerCertificate, SINGLE, REQUIRED),
        ("ca_certificate", enums.Tag.CACertificate, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.GetTLSCertificate

    def __init__(self, server_certificate=None, ca_certificate=None):
        self.server_certificate = server_certificate
        self.ca_certificate = ca_certificate
        super(GetTLSCertificateResponsePayload, self).__init__()


class GetUserObjectPermissionRequestPayload(RequestPayload):
    """
    GetUserObjectPermissionRequestPayload is the payload of a Get User Permission to an object
    Applications Operation Request message.
    
    Args:
        unique_identifier (str): optional
        user_name (str): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("user_name", enums.Tag.UserName, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetUserObjectPermission

    def __init__(self, unique_identifier=None, user_name=None):
        self.unique_identifier = unique_identifier
        self.user_name = user_name
        super(GetUserObjectPermissionRequestPayload, self).__init__()


class GetUserObjectPermissionResponsePayload(ResponsePayload):
    """
    GetUserObjectPermissionResponsePayload is the payload of a Get User Permission to an object
    Response message
    
    Args:
        permission_mask (int): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("permission_mask", enums.Tag.PermissionMask, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetUserObjectPermission

    def __init__(self, permission_mask=None):
        self.permission_mask = permission_mask
        super(GetUserObjectPermissionResponsePayload, self).__init__()


class GetVHSMUsageRequestPayload(RequestPayload):
    """
    GetVHSMUsageRequestPayload is the payload content of a GetVHSMUsage
    Operation Request.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.GetVHSMUsage

    def __init__(self):
        super(GetVHSMUsageRequestPayload, self).__init__()


class GetVHSMUsageResponsePayload(ResponsePayload):
    """
    GetVHSMUsageResponsePayload is the payload content of a GetVHSMUsage
    Operation Response.
    
    Args:
        usage (types.Usage): required
        se_application_usage_list (list(types.SEApplicationUsage)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("usage", enums.Tag.Usage, SINGLE, REQUIRED),
        ("se_application_usage_list", enums.Tag.SEApplicationUsage, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.GetVHSMUsage

    def __init__(self, usage=None, se_application_usage_list=None):
        self.usage = usage
        self.se_application_usage_list = se_application_usage_list
        super(GetVHSMUsageResponsePayload, self).__init__()


class HashRequestPayload(RequestPayload):
    """
    HashRequestPayload holds the information of a Hash Operation Request
    Payload.
    
    Args:
        cryptographic_parameters (types.CryptographicParameters): required
        data (bytes): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, REQUIRED),
        ("data", enums.Tag.Data, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Hash

    def __init__(self, cryptographic_parameters=None, data=None, correlation_value=None, init_indicator=None, final_indicator=None):
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        super(HashRequestPayload, self).__init__()


class HashResponsePayload(ResponsePayload):
    """
    HashResponsePayload holds the information of a Hash Operation Response
    Payload.
    
    Args:
        data (bytes): optional
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("data", enums.Tag.Data, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Hash

    def __init__(self, data=None, correlation_value=None):
        self.data = data
        self.correlation_value = correlation_value
        super(HashResponsePayload, self).__init__()


class ImportPhysicalHSMRequestPayload(RequestPayload):
    """
    ImportPhysicalHSMRequestPayload is the payload of a Get SE
    Data Operation Request message.
    
    Args:
        data (bytes): optional
        certificate (types.Certificate): optional
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("data", enums.Tag.Data, SINGLE, MAYBE_REQUIRED),
        ("certificate", enums.Tag.Certificate, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, MAYBE_REQUIRED)
    ]
    OPERATION = enums.Operation.ImportPhysicalHSM

    def __init__(self, data=None, certificate=None, correlation_value=None):
        self.data = data
        self.certificate = certificate
        self.correlation_value = correlation_value
        super(ImportPhysicalHSMRequestPayload, self).__init__()


class ImportPhysicalHSMResponsePayload(ResponsePayload):
    """
    ImportPhysicalHSMResponsePayload is the payload of a Get SE
    Data Operation Response message
    
    Args:
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, MAYBE_REQUIRED)
    ]
    OPERATION = enums.Operation.ImportPhysicalHSM

    def __init__(self, correlation_value=None):
        self.correlation_value = correlation_value
        super(ImportPhysicalHSMResponsePayload, self).__init__()


class ImportVirtualHSMRequestPayload(RequestPayload):
    """
    ImportVirtualHSMRequestPayload is the payload of a Get SE
    Data Operation Request message.
    
    Args:
        vhsm_name (str): optional
        ttlv_port (int): optional
        https_port (int): optional
        vco_name (str): optional
        vhsm_options (types.VHSMOptions): optional
        data (bytes): optional
        correlation_value (bytes): optional
        certificate (types.Certificate): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("vhsm_name", enums.Tag.VHSMName, SINGLE, OPTIONAL),
        ("ttlv_port", enums.Tag.TTLVPort, SINGLE, OPTIONAL),
        ("https_port", enums.Tag.HTTPSPort, SINGLE, OPTIONAL),
        ("vco_name", enums.Tag.VCOName, SINGLE, OPTIONAL),
        ("vhsm_options", enums.Tag.VHSMOptions, SINGLE, OPTIONAL),
        ("data", enums.Tag.Data, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, MAYBE_REQUIRED),
        ("certificate", enums.Tag.Certificate, SINGLE, MAYBE_REQUIRED)
    ]
    OPERATION = enums.Operation.ImportVirtualHSM

    def __init__(self, vhsm_name=None, ttlv_port=None, https_port=None, vco_name=None, vhsm_options=None, data=None, correlation_value=None, certificate=None):
        self.vhsm_name = vhsm_name
        self.ttlv_port = ttlv_port
        self.https_port = https_port
        self.vco_name = vco_name
        self.vhsm_options = vhsm_options
        self.data = data
        self.correlation_value = correlation_value
        self.certificate = certificate
        super(ImportVirtualHSMRequestPayload, self).__init__()


class ImportVirtualHSMResponsePayload(ResponsePayload):
    """
    ImportVirtualHSMResponsePayload is the payload of a Get SE
    Data Operation Response message
    
    Args:
        correlation_value (bytes): optional
        vhsm_unique_id (int): optional
        certificate (types.Certificate): optional
        vco_pin (str): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, MAYBE_REQUIRED),
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, MAYBE_REQUIRED),
        ("certificate", enums.Tag.Certificate, SINGLE, MAYBE_REQUIRED),
        ("vco_pin", enums.Tag.VCOPin, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.ImportVirtualHSM

    def __init__(self, correlation_value=None, vhsm_unique_id=None, certificate=None, vco_pin=None):
        self.correlation_value = correlation_value
        self.vhsm_unique_id = vhsm_unique_id
        self.certificate = certificate
        self.vco_pin = vco_pin
        super(ImportVirtualHSMResponsePayload, self).__init__()


class KeyBlock(KmipObject):
    """
    KeyBlock is a structure used to encapsulate all of the information that is
    closely associated with a cryptographic key.
    
    Args:
        key_format_type (enums.KeyFormatType): required
        key_compression_type (enums.KeyCompressionType): optional
        key_value (types.KeyValue): optional
        cryptographic_algorithm (enums.CryptographicAlgorithm): optional
        cryptographic_length (int): optional
        key_wrapping_data (types.KeyWrappingData): optional
    """

    TAG = enums.Tag.KeyBlock
    FIELDS = [
        ("key_format_type", enums.Tag.KeyFormatType, SINGLE, REQUIRED),
        ("key_compression_type", enums.Tag.KeyCompressionType, SINGLE, OPTIONAL),
        ("key_value", enums.Tag.KeyValue, SINGLE, OPTIONAL),
        ("cryptographic_algorithm", enums.Tag.CryptographicAlgorithm, SINGLE, MAYBE_REQUIRED),
        ("cryptographic_length", enums.Tag.CryptographicLength, SINGLE, MAYBE_REQUIRED),
        ("key_wrapping_data", enums.Tag.KeyWrappingData, SINGLE, OPTIONAL)
    ]

    def __init__(self, key_format_type=None, key_compression_type=None, key_value=None, cryptographic_algorithm=None, cryptographic_length=None, key_wrapping_data=None):
        self.key_format_type = key_format_type
        self.key_compression_type = key_compression_type
        self.key_value = key_value
        self.cryptographic_algorithm = cryptographic_algorithm
        self.cryptographic_length = cryptographic_length
        self.key_wrapping_data = key_wrapping_data
        super(KeyBlock, self).__init__()


class KeyValueLocation(AttributeValue):
    """
    KeyValueLocation is used to indicate the location of the Key Value absent
    from the object being registered.
    
    Args:
        key_value_location_value (str): required
        key_value_location_type (enums.KeyValueLocationType): required
    """

    TAG = enums.Tag.KeyValueLocation
    FIELDS = [
        ("key_value_location_value", enums.Tag.KeyValueLocationValue, SINGLE, REQUIRED),
        ("key_value_location_type", enums.Tag.KeyValueLocationType, SINGLE, REQUIRED)
    ]

    def __init__(self, key_value_location_value=None, key_value_location_type=None):
        self.key_value_location_value = key_value_location_value
        self.key_value_location_type = key_value_location_type
        super(KeyValueLocation, self).__init__()


class KeyValue(KmipObject):
    """
    KeyValueStructure contains the key material, either as a byte string or as a
    Transparent Key structure
    
    Args:
        key_material (types.TransparentDHPrivateKey, types.TransparentDHPublicKey, types.TransparentDSAPrivateKey, types.TransparentDSAPublicKey, types.TransparentECDSAPrivateKey, types.TransparentECDSAPublicKey, types.TransparentECDSPrivateKey, types.TransparentECDSPublicKey, types.TransparentECMQVPrivateKey, types.TransparentECMQVPublicKey, types.TransparentECPrivateKey, types.TransparentECPublicKey, types.TransparentRSAPrivateKey, types.TransparentRSAPublicKey, types.TransparentSymmetricKey): required
        attribute_list (list(types.Attribute)): optional
    """

    TAG = enums.Tag.KeyValue
    FIELDS = [
        ("key_material", enums.Tag.KeyMaterial, SINGLE, REQUIRED),
        ("attribute_list", enums.Tag.Attribute, MULTI, OPTIONAL)
    ]

    def __init__(self, key_material=None, attribute_list=None):
        self.key_material = key_material
        self.attribute_list = attribute_list
        super(KeyValue, self).__init__()


class KeyWrappingData(KmipObject):
    """
    KeyWrappingData are OPTIONAL information about a cryptographic key wrapping
    mechanism used to wrap a Key Value
    
    Args:
        wrapping_method (enums.WrappingMethod): required
        encryption_key_information (types.EncryptionKeyInformation): optional
        mac_signature_key_information (types.MACSignatureKeyInformation): optional
        mac_signature (bytes): optional
        iv_counter_nonce (bytes): optional
        encoding_option (enums.EncodingOption): optional
    """

    TAG = enums.Tag.KeyWrappingData
    FIELDS = [
        ("wrapping_method", enums.Tag.WrappingMethod, SINGLE, REQUIRED),
        ("encryption_key_information", enums.Tag.EncryptionKeyInformation, SINGLE, OPTIONAL),
        ("mac_signature_key_information", enums.Tag.MACSignatureKeyInformation, SINGLE, OPTIONAL),
        ("mac_signature", enums.Tag.MACSignature, SINGLE, OPTIONAL),
        ("iv_counter_nonce", enums.Tag.IVCounterNonce, SINGLE, OPTIONAL),
        ("encoding_option", enums.Tag.EncodingOption, SINGLE, OPTIONAL)
    ]

    def __init__(self, wrapping_method=None, encryption_key_information=None, mac_signature_key_information=None, mac_signature=None, iv_counter_nonce=None, encoding_option=None):
        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.mac_signature = mac_signature
        self.iv_counter_nonce = iv_counter_nonce
        self.encoding_option = encoding_option
        super(KeyWrappingData, self).__init__()


class KeyWrappingSpecification(KmipObject):
    """
    KeyWrappingSpecification describes the key wrapping mechanism
    It SHALL be included inside the operation request if clients request the
    server to return a wrapped key
    
    Args:
        wrapping_method (enums.WrappingMethod): required
        encryption_key_information (types.EncryptionKeyInformation): optional
        mac_signature_key_information (types.MACSignatureKeyInformation): optional
        attribute_name_list (list(str)): optional
        encoding_option (enums.EncodingOption): optional
    """

    TAG = enums.Tag.KeyWrappingSpecification
    FIELDS = [
        ("wrapping_method", enums.Tag.WrappingMethod, SINGLE, REQUIRED),
        ("encryption_key_information", enums.Tag.EncryptionKeyInformation, SINGLE, OPTIONAL),
        ("mac_signature_key_information", enums.Tag.MACSignatureKeyInformation, SINGLE, OPTIONAL),
        ("attribute_name_list", enums.Tag.AttributeName, MULTI, OPTIONAL),
        ("encoding_option", enums.Tag.EncodingOption, SINGLE, OPTIONAL)
    ]

    def __init__(self, wrapping_method=None, encryption_key_information=None, mac_signature_key_information=None, attribute_name_list=None, encoding_option=None):
        self.wrapping_method = wrapping_method
        self.encryption_key_information = encryption_key_information
        self.mac_signature_key_information = mac_signature_key_information
        self.attribute_name_list = attribute_name_list
        self.encoding_option = encoding_option
        super(KeyWrappingSpecification, self).__init__()


class LanInterfaceInformation(KmipObject):
    """
    LanInterfaceInformation holds information about a Lan Interface.
    
    Args:
        lan_interface (enums.LanInterface): required
        lan_ip (str): required
        lan_mask (str): required
        lan_gateway (str): optional
        lan_dns_list (list(str)): optional
    """

    TAG = enums.Tag.LanInterfaceInformation
    FIELDS = [
        ("lan_interface", enums.Tag.LanInterface, SINGLE, REQUIRED),
        ("lan_ip", enums.Tag.LanIP, SINGLE, REQUIRED),
        ("lan_mask", enums.Tag.LanMask, SINGLE, REQUIRED),
        ("lan_gateway", enums.Tag.LanGateway, SINGLE, OPTIONAL),
        ("lan_dns_list", enums.Tag.LanDNS, MULTI, OPTIONAL)
    ]

    def __init__(self, lan_interface=None, lan_ip=None, lan_mask=None, lan_gateway=None, lan_dns_list=None):
        self.lan_interface = lan_interface
        self.lan_ip = lan_ip
        self.lan_mask = lan_mask
        self.lan_gateway = lan_gateway
        self.lan_dns_list = lan_dns_list
        super(LanInterfaceInformation, self).__init__()


class Link(AttributeValue):
    """
    Link attribute is used to create a link from one Managed Cryptographic Object to another
    
    Args:
        link_type (enums.LinkType): required
        linked_object_identifier (str): required
    """

    TAG = enums.Tag.Link
    FIELDS = [
        ("link_type", enums.Tag.LinkType, SINGLE, REQUIRED),
        ("linked_object_identifier", enums.Tag.LinkedObjectIdentifier, SINGLE, REQUIRED)
    ]

    def __init__(self, link_type=None, linked_object_identifier=None):
        self.link_type = link_type
        self.linked_object_identifier = linked_object_identifier
        super(Link, self).__init__()


class ListSEApplicationsRequestPayload(RequestPayload):
    """
    ListSEAppsRequestPayload is the payload of a List SE
    Applications Operation Request message.
    
    Args:
        maximum_items (int): optional
        offset_items (int): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("maximum_items", enums.Tag.MaximumItems, SINGLE, OPTIONAL),
        ("offset_items", enums.Tag.OffsetItems, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.ListSEApplications

    def __init__(self, maximum_items=None, offset_items=None):
        self.maximum_items = maximum_items
        self.offset_items = offset_items
        super(ListSEApplicationsRequestPayload, self).__init__()


class ListSEApplicationsResponsePayload(ResponsePayload):
    """
    ListSEAppsResponsePayload is the payload of a List SE
    Applications Operation Response message
    
    Args:
        located_items (int): optional
        application_basic_info_list (list(types.ApplicationBasicInfo)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("located_items", enums.Tag.LocatedItems, SINGLE, OPTIONAL),
        ("application_basic_info_list", enums.Tag.ApplicationBasicInfo, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.ListSEApplications

    def __init__(self, located_items=None, application_basic_info_list=None):
        self.located_items = located_items
        self.application_basic_info_list = application_basic_info_list
        super(ListSEApplicationsResponsePayload, self).__init__()


class ListUsersRequestPayload(RequestPayload):
    """
    ListUsersRequestPayload is the payload of a List Users Operation
    Request message.
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.ListUsers

    def __init__(self):
        super(ListUsersRequestPayload, self).__init__()


class ListUsersResponsePayload(ResponsePayload):
    """
    ListUsersResponsePayload is the payload of a List Users Operation
    Response message
    
    Args:
        located_items (int): optional
        user_information_list (list(types.UserInformation)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("located_items", enums.Tag.LocatedItems, SINGLE, OPTIONAL),
        ("user_information_list", enums.Tag.UserInformation, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.ListUsers

    def __init__(self, located_items=None, user_information_list=None):
        self.located_items = located_items
        self.user_information_list = user_information_list
        super(ListUsersResponsePayload, self).__init__()


class ListVirtualHSMsRequestPayload(RequestPayload):
    """
    ListVirtualHSMsRequestPayload is the payload of a List Virtual HSMs Operation
    Request message.
    
    Args:
        maximum_items (int): optional
        offset_items (int): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("maximum_items", enums.Tag.MaximumItems, SINGLE, OPTIONAL),
        ("offset_items", enums.Tag.OffsetItems, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.ListVirtualHSMs

    def __init__(self, maximum_items=None, offset_items=None):
        self.maximum_items = maximum_items
        self.offset_items = offset_items
        super(ListVirtualHSMsRequestPayload, self).__init__()


class ListVirtualHSMsResponsePayload(ResponsePayload):
    """
    ListVirtualHSMsResponsePayload is the payload of a List Virtual HSMs Operation
    Response message
    
    Args:
        located_items (int): optional
        virtual_hsm_data_list (list(types.VirtualHSMData)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("located_items", enums.Tag.LocatedItems, SINGLE, OPTIONAL),
        ("virtual_hsm_data_list", enums.Tag.VirtualHSMData, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.ListVirtualHSMs

    def __init__(self, located_items=None, virtual_hsm_data_list=None):
        self.located_items = located_items
        self.virtual_hsm_data_list = virtual_hsm_data_list
        super(ListVirtualHSMsResponsePayload, self).__init__()


class LoadKeyRequestPayload(RequestPayload):
    """
    
    Args:
        unique_identifier (str): required
        object_type (enums.ObjectType): required
        operation (enums.Operation): required
        cryptographic_usage_mask (int): required
        cryptographic_parameters (types.CryptographicParameters): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("object_type", enums.Tag.ObjectType, SINGLE, REQUIRED),
        ("operation", enums.Tag.Operation, SINGLE, REQUIRED),
        ("cryptographic_usage_mask", enums.Tag.CryptographicUsageMask, SINGLE, REQUIRED),
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.LoadKey

    def __init__(self, unique_identifier=None, object_type=None, operation=None, cryptographic_usage_mask=None, cryptographic_parameters=None):
        self.unique_identifier = unique_identifier
        self.object_type = object_type
        self.operation = operation
        self.cryptographic_usage_mask = cryptographic_usage_mask
        self.cryptographic_parameters = cryptographic_parameters
        super(LoadKeyRequestPayload, self).__init__()


class LoadKeyResponsePayload(ResponsePayload):
    """
    
    Args:
        unique_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.LoadKey

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(LoadKeyResponsePayload, self).__init__()


class LocateRequestPayload(RequestPayload):
    """
    LocateRequestPayload describes the payload of a Locate Operation Request
    
    Args:
        maximum_items (int): optional
        offset_items (int): optional
        storage_status_mask (int): optional
        object_group_member (enums.ObjectGroupMember): optional
        attribute_list (list(types.Attribute)): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("maximum_items", enums.Tag.MaximumItems, SINGLE, OPTIONAL),
        ("offset_items", enums.Tag.OffsetItems, SINGLE, OPTIONAL),
        ("storage_status_mask", enums.Tag.StorageStatusMask, SINGLE, OPTIONAL),
        ("object_group_member", enums.Tag.ObjectGroupMember, SINGLE, OPTIONAL),
        ("attribute_list", enums.Tag.Attribute, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.Locate

    def __init__(self, maximum_items=None, offset_items=None, storage_status_mask=None, object_group_member=None, attribute_list=None):
        self.maximum_items = maximum_items
        self.offset_items = offset_items
        self.storage_status_mask = storage_status_mask
        self.object_group_member = object_group_member
        self.attribute_list = attribute_list
        super(LocateRequestPayload, self).__init__()


class LocateResponsePayload(ResponsePayload):
    """
    LocateResponsePayload describes the payload of a response to a Locate
    Operation Request
    
    Args:
        located_items (int): optional
        unique_identifier_list (list(str)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("located_items", enums.Tag.LocatedItems, SINGLE, OPTIONAL),
        ("unique_identifier_list", enums.Tag.UniqueIdentifier, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.Locate

    def __init__(self, located_items=None, unique_identifier_list=None):
        self.located_items = located_items
        self.unique_identifier_list = unique_identifier_list
        super(LocateResponsePayload, self).__init__()


class MACRequestPayload(RequestPayload):
    """
    MACRequestPayload holds the information of a MAC Operation Request
    Payload.
    
    Args:
        unique_identifier (str): optional
        cryptographic_parameters (types.CryptographicParameters): optional
        data (bytes): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, OPTIONAL),
        ("data", enums.Tag.Data, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.MAC

    def __init__(self, unique_identifier=None, cryptographic_parameters=None, data=None, correlation_value=None, init_indicator=None, final_indicator=None):
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        super(MACRequestPayload, self).__init__()


class MACResponsePayload(ResponsePayload):
    """
    MACResponsePayload holds the information of a MAC Operation Response
    Payload.
    
    Args:
        unique_identifier (str): required
        mac_data (bytes): optional
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("mac_data", enums.Tag.MACData, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.MAC

    def __init__(self, unique_identifier=None, mac_data=None, correlation_value=None):
        self.unique_identifier = unique_identifier
        self.mac_data = mac_data
        self.correlation_value = correlation_value
        super(MACResponsePayload, self).__init__()


class MACVerifyRequestPayload(RequestPayload):
    """
    MACVerifyRequestPayload holds the information of a MACVerify
    Operation Request Payload.
    
    Args:
        unique_identifier (str): optional
        cryptographic_parameters (types.CryptographicParameters): optional
        data (bytes): optional
        mac_data (bytes): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, OPTIONAL),
        ("data", enums.Tag.Data, SINGLE, OPTIONAL),
        ("mac_data", enums.Tag.MACData, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.MACVerify

    def __init__(self, unique_identifier=None, cryptographic_parameters=None, data=None, mac_data=None, correlation_value=None, init_indicator=None, final_indicator=None):
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.mac_data = mac_data
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        super(MACVerifyRequestPayload, self).__init__()


class MACVerifyResponsePayload(ResponsePayload):
    """
    MACVerifyResponsePayload holds the information of a MACVerify
    Operation Response Payload.
    
    Args:
        unique_identifier (str): required
        validity_indicator (enums.ValidityIndicator): required
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("validity_indicator", enums.Tag.ValidityIndicator, SINGLE, REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.MACVerify

    def __init__(self, unique_identifier=None, validity_indicator=None, correlation_value=None):
        self.unique_identifier = unique_identifier
        self.validity_indicator = validity_indicator
        self.correlation_value = correlation_value
        super(MACVerifyResponsePayload, self).__init__()


class MessageExtension(KmipObject):
    """
    MessageExtension is an OPTIONAL structure that MAY be appended to any
    BatchItem. It is used to extend protocol messagesfor the purpose of adding
    vendor-specified extensions.
    
    Args:
        vendor_identification (str): optional
        criticality_indicator (bool): optional
        vendor_extension: optional
    """

    TAG = enums.Tag.MessageExtension
    FIELDS = [
        ("vendor_identification", enums.Tag.VendorIdentification, SINGLE, OPTIONAL),
        ("criticality_indicator", enums.Tag.CriticalityIndicator, SINGLE, OPTIONAL),
        ("vendor_extension", enums.Tag.VendorExtension, SINGLE, OPTIONAL)
    ]

    def __init__(self, vendor_identification=None, criticality_indicator=None, vendor_extension=None):
        self.vendor_identification = vendor_identification
        self.criticality_indicator = criticality_indicator
        self.vendor_extension = vendor_extension
        super(MessageExtension, self).__init__()


class ModifyAttributeRequestPayload(RequestPayload):
    """
    ModifyAttributeRequestPayload is the payload of a Modify Attribute Operation
    Request message
    
    Args:
        unique_identifier (str): optional
        attribute (types.Attribute): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("attribute", enums.Tag.Attribute, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ModifyAttribute

    def __init__(self, unique_identifier=None, attribute=None):
        self.unique_identifier = unique_identifier
        self.attribute = attribute
        super(ModifyAttributeRequestPayload, self).__init__()


class ModifyAttributeResponsePayload(ResponsePayload):
    """
    ModifyAttributeResponsePayload is the payload of a Modify Attribute Operation
    Response message
    
    Args:
        unique_identifier (str): required
        attribute (types.Attribute): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("attribute", enums.Tag.Attribute, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ModifyAttribute

    def __init__(self, unique_identifier=None, attribute=None):
        self.unique_identifier = unique_identifier
        self.attribute = attribute
        super(ModifyAttributeResponsePayload, self).__init__()


class Name(AttributeValue):
    """
    Name is a structure used to locate an object
    
    Args:
        name_value (str): required
        name_type (enums.NameType): required
    """

    TAG = enums.Tag.Name
    FIELDS = [
        ("name_value", enums.Tag.NameValue, SINGLE, REQUIRED),
        ("name_type", enums.Tag.NameType, SINGLE, REQUIRED)
    ]

    def __init__(self, name_value=None, name_type=None):
        self.name_value = name_value
        self.name_type = name_type
        super(Name, self).__init__()


class Nonce(KmipObject):
    """
    Nonce base object is used by the server to send a random value to the client
    
    Args:
        nonce_id (bytes): required
        nonce_value (bytes): required
    """

    TAG = enums.Tag.Nonce
    FIELDS = [
        ("nonce_id", enums.Tag.NonceID, SINGLE, REQUIRED),
        ("nonce_value", enums.Tag.NonceValue, SINGLE, REQUIRED)
    ]

    def __init__(self, nonce_id=None, nonce_value=None):
        self.nonce_id = nonce_id
        self.nonce_value = nonce_value
        super(Nonce, self).__init__()


class OpaqueObject(ManagedObject):
    """
    OpaqueObject is a Managed Object that the key management server is possibly
    not able to interpret.
    
    Args:
        opaque_data_value (bytes): required
    """

    TAG = enums.Tag.OpaqueObject
    FIELDS = [
        ("opaque_data_value", enums.Tag.OpaqueDataValue, SINGLE, REQUIRED)
    ]

    def __init__(self, opaque_data_value=None):
        self.opaque_data_value = opaque_data_value
        super(OpaqueObject, self).__init__()


class OverwriteSEApplicationRequestPayload(RequestPayload):
    """
    OverwriteSEAppRequestPayload is the payload of a Overwrite SE
    Application Operation Request message.
    
    Args:
        unique_identifier (str): required
        file_type (enums.FileType): required
        application_entry_point (str): optional
        file_data (bytes): required
        se_language (enums.SELanguage): required
        application_name (str): optional
        start_on_boot (bool): optional
        non_stop (bool): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
        application_port_list (list(types.ApplicationPort)): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("file_type", enums.Tag.FileType, SINGLE, REQUIRED),
        ("application_entry_point", enums.Tag.ApplicationEntryPoint, SINGLE, MAYBE_REQUIRED),
        ("file_data", enums.Tag.FileData, SINGLE, REQUIRED),
        ("se_language", enums.Tag.SELanguage, SINGLE, REQUIRED),
        ("application_name", enums.Tag.ApplicationName, SINGLE, OPTIONAL),
        ("start_on_boot", enums.Tag.StartOnBoot, SINGLE, OPTIONAL),
        ("non_stop", enums.Tag.NonStop, SINGLE, OPTIONAL),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL),
        ("application_port_list", enums.Tag.ApplicationPort, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.OverwriteSEApplication

    def __init__(self, unique_identifier=None, file_type=None, application_entry_point=None, file_data=None, se_language=None, application_name=None, start_on_boot=None, non_stop=None, correlation_value=None, init_indicator=None, final_indicator=None, application_port_list=None):
        self.unique_identifier = unique_identifier
        self.file_type = file_type
        self.application_entry_point = application_entry_point
        self.file_data = file_data
        self.se_language = se_language
        self.application_name = application_name
        self.start_on_boot = start_on_boot
        self.non_stop = non_stop
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        self.application_port_list = application_port_list
        super(OverwriteSEApplicationRequestPayload, self).__init__()


class OverwriteSEApplicationResponsePayload(ResponsePayload):
    """
    OverwriteSEAppResponsePayload is the payload of a Overwrite SE
    Application Operation Response message
    
    Args:
        unique_identifier (str): required
        file_data_digest (bytes): required
        hashing_algorithm (enums.HashingAlgorithm): required
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("file_data_digest", enums.Tag.FileDataDigest, SINGLE, REQUIRED),
        ("hashing_algorithm", enums.Tag.HashingAlgorithm, SINGLE, REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.OverwriteSEApplication

    def __init__(self, unique_identifier=None, file_data_digest=None, hashing_algorithm=None, correlation_value=None):
        self.unique_identifier = unique_identifier
        self.file_data_digest = file_data_digest
        self.hashing_algorithm = hashing_algorithm
        self.correlation_value = correlation_value
        super(OverwriteSEApplicationResponsePayload, self).__init__()


class PGPKey(ManagedObject):
    """
    PGPKey is a Managed Object that is a text-based representation of a PGP key
    
    Args:
        pgp_key_version (int): required
        key_block (types.KeyBlock): required
    """

    TAG = enums.Tag.PGPKey
    FIELDS = [
        ("pgp_key_version", enums.Tag.PGPKeyVersion, SINGLE, REQUIRED),
        ("key_block", enums.Tag.KeyBlock, SINGLE, REQUIRED)
    ]

    def __init__(self, pgp_key_version=None, key_block=None):
        self.pgp_key_version = pgp_key_version
        self.key_block = key_block
        super(PGPKey, self).__init__()


class PasswordCredential(KmipObject):
    """
    PasswordCredential is the defined type for the value of Credential when
    the CredentialType is Username and Password
    
    Args:
        username (str): required
        password (str): optional
    """

    TAG = enums.Tag.CredentialValue
    FIELDS = [
        ("username", enums.Tag.Username, SINGLE, REQUIRED),
        ("password", enums.Tag.Password, SINGLE, OPTIONAL)
    ]

    def __init__(self, username=None, password=None):
        self.username = username
        self.password = password
        super(PasswordCredential, self).__init__()


class PrivateKey(ManagedObject):
    """
    PrivateKey is the struct to hold the private portion of a asymmetric key pair
    
    Args:
        key_block (types.KeyBlock): required
    """

    TAG = enums.Tag.PrivateKey
    FIELDS = [
        ("key_block", enums.Tag.KeyBlock, SINGLE, REQUIRED)
    ]

    def __init__(self, key_block=None):
        self.key_block = key_block
        super(PrivateKey, self).__init__()


class ProfileInformation(KmipObject):
    """
    Profile Information base object contains details of the supported profiles
    
    Args:
        profile_name (enums.ProfileName): required
        server_uri (str): optional
        server_port (int): optional
    """

    TAG = enums.Tag.ProfileInformation
    FIELDS = [
        ("profile_name", enums.Tag.ProfileName, SINGLE, REQUIRED),
        ("server_uri", enums.Tag.ServerURI, SINGLE, OPTIONAL),
        ("server_port", enums.Tag.ServerPort, SINGLE, OPTIONAL)
    ]

    def __init__(self, profile_name=None, server_uri=None, server_port=None):
        self.profile_name = profile_name
        self.server_uri = server_uri
        self.server_port = server_port
        super(ProfileInformation, self).__init__()


class ProtocolVersion(KmipObject):
    """
    ProtocolVersion holds the KMIP version being used by the message sender
    
    Args:
        protocol_version_major (int): optional
        protocol_version_minor (int): optional
    """

    TAG = enums.Tag.ProtocolVersion
    FIELDS = [
        ("protocol_version_major", enums.Tag.ProtocolVersionMajor, SINGLE, OPTIONAL),
        ("protocol_version_minor", enums.Tag.ProtocolVersionMinor, SINGLE, OPTIONAL)
    ]

    def __init__(self, protocol_version_major=None, protocol_version_minor=None):
        self.protocol_version_major = protocol_version_major
        self.protocol_version_minor = protocol_version_minor
        super(ProtocolVersion, self).__init__()


class PublicKey(ManagedObject):
    """
    PublicKey is the struct to hold the public portion of a asymmetric key pair
    
    Args:
        key_block (types.KeyBlock): required
    """

    TAG = enums.Tag.PublicKey
    FIELDS = [
        ("key_block", enums.Tag.KeyBlock, SINGLE, REQUIRED)
    ]

    def __init__(self, key_block=None):
        self.key_block = key_block
        super(PublicKey, self).__init__()


class QueryRequestPayload(RequestPayload):
    """
    QueryRequestPayload is the payload of a Query Operation Request message
    
    Args:
        query_function_list (list(enums.QueryFunction)): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("query_function_list", enums.Tag.QueryFunction, MULTI, MAYBE_REQUIRED)
    ]
    OPERATION = enums.Operation.Query

    def __init__(self, query_function_list=None):
        self.query_function_list = query_function_list
        super(QueryRequestPayload, self).__init__()


class QueryResponsePayload(ResponsePayload):
    """
    QueryResponsePayload is the payload of a Query Operation Response message
    
    Args:
        operation_list (list(enums.Operation)): optional
        object_type_list (list(enums.ObjectType)): optional
        vendor_identification (str): optional
        server_information (types.ServerInformation): optional
        application_namespace_list (list(str)): optional
        extension_information_list (list(types.ExtensionInformation)): optional
        attestation_type_list (list(enums.AttestationType)): optional
        rng_parameters_list (list(types.RNGParameters)): optional
        profile_information_list (list(types.ProfileInformation)): optional
        validation_information_list (list(types.ValidationInformation)): optional
        capability_information_list (list(types.CapabilityInformation)): optional
        client_registration_method_list (list(enums.ClientRegistrationMethod)): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("operation_list", enums.Tag.Operation, MULTI, OPTIONAL),
        ("object_type_list", enums.Tag.ObjectType, MULTI, OPTIONAL),
        ("vendor_identification", enums.Tag.VendorIdentification, SINGLE, OPTIONAL),
        ("server_information", enums.Tag.ServerInformation, SINGLE, OPTIONAL),
        ("application_namespace_list", enums.Tag.ApplicationNamespace, MULTI, OPTIONAL),
        ("extension_information_list", enums.Tag.ExtensionInformation, MULTI, OPTIONAL),
        ("attestation_type_list", enums.Tag.AttestationType, MULTI, OPTIONAL),
        ("rng_parameters_list", enums.Tag.RNGParameters, MULTI, OPTIONAL),
        ("profile_information_list", enums.Tag.ProfileInformation, MULTI, OPTIONAL),
        ("validation_information_list", enums.Tag.ValidationInformation, MULTI, OPTIONAL),
        ("capability_information_list", enums.Tag.CapabilityInformation, MULTI, OPTIONAL),
        ("client_registration_method_list", enums.Tag.ClientRegistrationMethod, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.Query

    def __init__(self, operation_list=None, object_type_list=None, vendor_identification=None, server_information=None, application_namespace_list=None, extension_information_list=None, attestation_type_list=None, rng_parameters_list=None, profile_information_list=None, validation_information_list=None, capability_information_list=None, client_registration_method_list=None):
        self.operation_list = operation_list
        self.object_type_list = object_type_list
        self.vendor_identification = vendor_identification
        self.server_information = server_information
        self.application_namespace_list = application_namespace_list
        self.extension_information_list = extension_information_list
        self.attestation_type_list = attestation_type_list
        self.rng_parameters_list = rng_parameters_list
        self.profile_information_list = profile_information_list
        self.validation_information_list = validation_information_list
        self.capability_information_list = capability_information_list
        self.client_registration_method_list = client_registration_method_list
        super(QueryResponsePayload, self).__init__()


class RNGParameters(KmipObject):
    """
    RNG Parameters base object is a structure that contains a mandatory RNG
    Algorithm  and a set of OPTIONAL fields that describes a RNG.
    
    Args:
        rng_algorithm (enums.RNGAlgorithm): required
        cryptographic_algorithm (enums.CryptographicAlgorithm): optional
        cryptographic_length (int): optional
        hashing_algorithm (enums.HashingAlgorithm): optional
        drbg_algorithm (enums.DRBGAlgorithm): optional
        recommended_curve (enums.RecommendedCurve): optional
        fip_s186_variation (enums.FIPS186Variation): optional
        prediction_resistance (bool): optional
    """

    TAG = enums.Tag.RNGParameters
    FIELDS = [
        ("rng_algorithm", enums.Tag.RNGAlgorithm, SINGLE, REQUIRED),
        ("cryptographic_algorithm", enums.Tag.CryptographicAlgorithm, SINGLE, OPTIONAL),
        ("cryptographic_length", enums.Tag.CryptographicLength, SINGLE, OPTIONAL),
        ("hashing_algorithm", enums.Tag.HashingAlgorithm, SINGLE, OPTIONAL),
        ("drbg_algorithm", enums.Tag.DRBGAlgorithm, SINGLE, OPTIONAL),
        ("recommended_curve", enums.Tag.RecommendedCurve, SINGLE, OPTIONAL),
        ("fip_s186_variation", enums.Tag.FIPS186Variation, SINGLE, OPTIONAL),
        ("prediction_resistance", enums.Tag.PredictionResistance, SINGLE, OPTIONAL)
    ]

    def __init__(self, rng_algorithm=None, cryptographic_algorithm=None, cryptographic_length=None, hashing_algorithm=None, drbg_algorithm=None, recommended_curve=None, fip_s186_variation=None, prediction_resistance=None):
        self.rng_algorithm = rng_algorithm
        self.cryptographic_algorithm = cryptographic_algorithm
        self.cryptographic_length = cryptographic_length
        self.hashing_algorithm = hashing_algorithm
        self.drbg_algorithm = drbg_algorithm
        self.recommended_curve = recommended_curve
        self.fip_s186_variation = fip_s186_variation
        self.prediction_resistance = prediction_resistance
        super(RNGParameters, self).__init__()


class RNGRetrieveRequestPayload(RequestPayload):
    """
    RNGRetrieveRequestPayload is the payload of a RNG Retrieve Operation Request message.
    
    Args:
        data_length (int): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("data_length", enums.Tag.DataLength, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RNGRetrieve

    def __init__(self, data_length=None):
        self.data_length = data_length
        super(RNGRetrieveRequestPayload, self).__init__()


class RNGRetrieveResponsePayload(ResponsePayload):
    """
    RNGRetrieveResponsePayload is the payload of a RNG Retrieve Operation Response message
    
    Args:
        data (bytes): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("data", enums.Tag.Data, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RNGRetrieve

    def __init__(self, data=None):
        self.data = data
        super(RNGRetrieveResponsePayload, self).__init__()


class RNGSeedRequestPayload(RequestPayload):
    """
    RNGSeedRequestPayload is the payload of a RNG Seed Operation Request message
    
    Args:
        data (bytes): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("data", enums.Tag.Data, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RNGSeed

    def __init__(self, data=None):
        self.data = data
        super(RNGSeedRequestPayload, self).__init__()


class RNGSeedResponsePayload(ResponsePayload):
    """
    RNGSeedResponsePayload is the payload of a RNG Seed Operation Response message.
    
    Args:
        data_length (int): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("data_length", enums.Tag.DataLength, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RNGSeed

    def __init__(self, data_length=None):
        self.data_length = data_length
        super(RNGSeedResponsePayload, self).__init__()


class ReKeyRequestPayload(RequestPayload):
    """
    ReKeyRequestPayload is the payload of a Re-key Operation Request message
    
    Args:
        unique_identifier (str): optional
        offset (datetime.timedelta): optional
        template_attribute (types.TemplateAttribute): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("offset", enums.Tag.Offset, SINGLE, OPTIONAL),
        ("template_attribute", enums.Tag.TemplateAttribute, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.ReKey

    def __init__(self, unique_identifier=None, offset=None, template_attribute=None):
        self.unique_identifier = unique_identifier
        self.offset = offset
        self.template_attribute = template_attribute
        super(ReKeyRequestPayload, self).__init__()


class ReKeyResponsePayload(ResponsePayload):
    """
    ReKeyResponsePayload is the payload of a Re-key Operation Response
    message
    
    Args:
        unique_identifier (str): required
        template_attribute (types.TemplateAttribute): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("template_attribute", enums.Tag.TemplateAttribute, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.ReKey

    def __init__(self, unique_identifier=None, template_attribute=None):
        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute
        super(ReKeyResponsePayload, self).__init__()


class RegisterCertificateRequestPayload(RequestPayload):
    """
    RegisterCertificateRequestPayload is the payload of a Register
    Certificate Operation Request message.
    
    Args:
        user_certificate_request (bytes): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("user_certificate_request", enums.Tag.UserCertificateRequest, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RegisterCertificate

    def __init__(self, user_certificate_request=None):
        self.user_certificate_request = user_certificate_request
        super(RegisterCertificateRequestPayload, self).__init__()


class RegisterCertificateResponsePayload(ResponsePayload):
    """
    RegisterCertificateResponsePayload is the payload of a Register
    Certificate Operation Response message
    
    Args:
        user_certificate (bytes): required
        ca_certificate (bytes): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("user_certificate", enums.Tag.UserCertificate, SINGLE, REQUIRED),
        ("ca_certificate", enums.Tag.CACertificate, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RegisterCertificate

    def __init__(self, user_certificate=None, ca_certificate=None):
        self.user_certificate = user_certificate
        self.ca_certificate = ca_certificate
        super(RegisterCertificateResponsePayload, self).__init__()


class RegisterRequestPayload(RequestPayload):
    """
    RegisterRequestPayload holds the information of a Register Operation Request
    Payload.
    
    Args:
        object_type (enums.ObjectType): required
        template_attribute (types.TemplateAttribute): required
        object (types.Certificate, types.SymmetricKey, types.PGPKey, types.PrivateKey, types.PublicKey, types.SplitKey, types.Template, types.SecretData, types.OpaqueObject): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("object_type", enums.Tag.ObjectType, SINGLE, REQUIRED),
        ("template_attribute", enums.Tag.TemplateAttribute, SINGLE, REQUIRED),
        ("object", (enums.Tag.Certificate, enums.Tag.SymmetricKey, enums.Tag.PGPKey, enums.Tag.PrivateKey, enums.Tag.PublicKey, enums.Tag.SplitKey, enums.Tag.Template, enums.Tag.SecretData, enums.Tag.OpaqueObject,), SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.Register

    def __init__(self, object_type=None, template_attribute=None, object=None):
        self.object_type = object_type
        self.template_attribute = template_attribute
        self.object = object
        super(RegisterRequestPayload, self).__init__()


class RegisterResponsePayload(ResponsePayload):
    """
    RegisterResponsePayload holds the information of a Register Operation
    Response Payload.
    
    Args:
        unique_identifier (str): required
        template_attribute (types.TemplateAttribute): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("template_attribute", enums.Tag.TemplateAttribute, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Register

    def __init__(self, unique_identifier=None, template_attribute=None):
        self.unique_identifier = unique_identifier
        self.template_attribute = template_attribute
        super(RegisterResponsePayload, self).__init__()


class RegisterSEApplicationRequestPayload(RequestPayload):
    """
    RegisterSEAppRequestPayload is the payload of a Register SE
    Application Operation Request message.
    
    Args:
        file_type (enums.FileType): required
        application_entry_point (str): optional
        file_data (bytes): required
        se_language (enums.SELanguage): required
        application_name (str): required
        start_now (bool): optional
        start_on_boot (bool): optional
        non_stop (bool): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
        application_port_list (list(types.ApplicationPort)): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("file_type", enums.Tag.FileType, SINGLE, REQUIRED),
        ("application_entry_point", enums.Tag.ApplicationEntryPoint, SINGLE, MAYBE_REQUIRED),
        ("file_data", enums.Tag.FileData, SINGLE, REQUIRED),
        ("se_language", enums.Tag.SELanguage, SINGLE, REQUIRED),
        ("application_name", enums.Tag.ApplicationName, SINGLE, REQUIRED),
        ("start_now", enums.Tag.StartNow, SINGLE, OPTIONAL),
        ("start_on_boot", enums.Tag.StartOnBoot, SINGLE, OPTIONAL),
        ("non_stop", enums.Tag.NonStop, SINGLE, OPTIONAL),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL),
        ("application_port_list", enums.Tag.ApplicationPort, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.RegisterSEApplication

    def __init__(self, file_type=None, application_entry_point=None, file_data=None, se_language=None, application_name=None, start_now=None, start_on_boot=None, non_stop=None, correlation_value=None, init_indicator=None, final_indicator=None, application_port_list=None):
        self.file_type = file_type
        self.application_entry_point = application_entry_point
        self.file_data = file_data
        self.se_language = se_language
        self.application_name = application_name
        self.start_now = start_now
        self.start_on_boot = start_on_boot
        self.non_stop = non_stop
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        self.application_port_list = application_port_list
        super(RegisterSEApplicationRequestPayload, self).__init__()


class RegisterSEApplicationResponsePayload(ResponsePayload):
    """
    RegisterSEAppResponsePayload is the payload of a Register SE
    Application Operation Response message
    
    Args:
        file_data_digest (bytes): required
        hashing_algorithm (enums.HashingAlgorithm): required
        unique_identifier (str): required
        instance_identifier (str): required
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("file_data_digest", enums.Tag.FileDataDigest, SINGLE, REQUIRED),
        ("hashing_algorithm", enums.Tag.HashingAlgorithm, SINGLE, REQUIRED),
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.RegisterSEApplication

    def __init__(self, file_data_digest=None, hashing_algorithm=None, unique_identifier=None, instance_identifier=None, correlation_value=None):
        self.file_data_digest = file_data_digest
        self.hashing_algorithm = hashing_algorithm
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        self.correlation_value = correlation_value
        super(RegisterSEApplicationResponsePayload, self).__init__()


class RemoveSEApplicationInstanceRequestPayload(RequestPayload):
    """
    RemoveSEAppInstanceRequestPayload is the payload of a Remove SE Application
    Instance Operation Request message.
    
    Args:
        unique_identifier (str): required
        instance_identifier (str): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RemoveSEApplicationInstance

    def __init__(self, unique_identifier=None, instance_identifier=None):
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        super(RemoveSEApplicationInstanceRequestPayload, self).__init__()


class RemoveSEApplicationInstanceResponsePayload(ResponsePayload):
    """
    RemoveSEAppInstanceResponsePayload is the payload of a Remove SE Application
    Instance Operation Response message
    
    Args:
        unique_identifier (str): required
        instance_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RemoveSEApplicationInstance

    def __init__(self, unique_identifier=None, instance_identifier=None):
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        super(RemoveSEApplicationInstanceResponsePayload, self).__init__()


class RequestBatchItem(KmipObject):
    """
    RequestBatchItem holds the information of a KMIP request message batch item.
    
    Args:
        operation (enums.Operation): required
        unique_batch_item_id (bytes): optional
        request_payload (types.ActivateRequestPayload, types.ActivateVirtualHSMRequestPayload, types.AddAttributeRequestPayload, types.CallSEApplicationCommandRequestPayload, types.ChangePasswordRequestPayload, types.CheckRequestPayload, types.CheckSEApplicationPortAvailableRequestPayload, types.ClearSEApplicationDirectoryRequestPayload, types.ConfigureNetworkRequestPayload, types.CreateKeyPairRequestPayload, types.CreateRequestPayload, types.CreateUserRequestPayload, types.CreateVirtualHSMRequestPayload, types.DeactivateVirtualHSMRequestPayload, types.DecryptRequestPayload, types.DeleteAttributeRequestPayload, types.DeleteSEApplicationRequestPayload, types.DeleteUserRequestPayload, types.DeleteVirtualHSMRequestPayload, types.DestroyRequestPayload, types.DiscoverVersionsRequestPayload, types.EditVirtualHSMRequestPayload, types.EncryptRequestPayload, types.ExportPhysicalHSMRequestPayload, types.ExportVirtualHSMRequestPayload, types.FirmwareUpdateRequestPayload, types.GetAttributeListRequestPayload, types.GetAttributesRequestPayload, types.GetDeviceInformationRequestPayload, types.GetDeviceTimeRequestPayload, types.GetLogLevelRequestPayload, types.GetNetworkConfigurationRequestPayload, types.GetPHSMUsageRequestPayload, types.GetRequestPayload, types.GetRequesterTypeRequestPayload, types.GetSEApplicationStateRequestPayload, types.GetSEApplicationUsageRequestPayload, types.GetSEApplicationDataRequestPayload, types.GetSNMPDataRequestPayload, types.GetSystemLogRequestPayload, types.GetTLSCertificateRequestPayload, types.GetUserObjectPermissionRequestPayload, types.GetVHSMUsageRequestPayload, types.HashRequestPayload, types.ImportPhysicalHSMRequestPayload, types.ImportVirtualHSMRequestPayload, types.ListSEApplicationsRequestPayload, types.ListUsersRequestPayload, types.ListVirtualHSMsRequestPayload, types.LoadKeyRequestPayload, types.LocateRequestPayload, types.MACRequestPayload, types.MACVerifyRequestPayload, types.ModifyAttributeRequestPayload, types.OverwriteSEApplicationRequestPayload, types.QueryRequestPayload, types.RNGRetrieveRequestPayload, types.RNGSeedRequestPayload, types.ReKeyRequestPayload, types.RegisterCertificateRequestPayload, types.RegisterRequestPayload, types.RegisterSEApplicationRequestPayload, types.RemoveSEApplicationInstanceRequestPayload, types.ResetPasswordRequestPayload, types.RestartRequestPayload, types.RestartSEApplicationRequestPayload, types.RevokeRequestPayload, types.SetDateTimeRequestPayload, types.SetLogLevelRequestPayload, types.SetSNMPDataRequestPayload, types.SetUserObjectPermissionRequestPayload, types.ShutdownRequestPayload, types.SignRequestPayload, types.SignatureVerifyRequestPayload, types.StartSEApplicationRequestPayload, types.StopSEApplicationRequestPayload, types.UploadLogoImageRequestPayload): required
        message_extension (types.MessageExtension): optional
    """

    TAG = enums.Tag.BatchItem
    FIELDS = [
        ("operation", enums.Tag.Operation, SINGLE, REQUIRED),
        ("unique_batch_item_id", enums.Tag.UniqueBatchItemID, SINGLE, MAYBE_REQUIRED),
        ("request_payload", enums.Tag.RequestPayload, SINGLE, REQUIRED),
        ("message_extension", enums.Tag.MessageExtension, SINGLE, OPTIONAL)
    ]

    def __init__(self, operation=None, unique_batch_item_id=None, request_payload=None, message_extension=None):
        self.operation = operation
        self.unique_batch_item_id = unique_batch_item_id
        self.request_payload = request_payload
        self.message_extension = message_extension
        super(RequestBatchItem, self).__init__()


class RequestHeader(KmipObject):
    """
    RequestHeader holds the information of a KMIP request message header.
    
    Args:
        protocol_version (types.ProtocolVersion): required
        client_correlation_value (str): optional
        maximum_response_size (int): optional
        asynchronous_indicator (bool): optional
        attestation_capable_indicator (bool): optional
        attestation_type_list (list(enums.AttestationType)): optional
        authentication (types.Authentication): optional
        batch_error_continuation_option (enums.BatchErrorContinuationOption): optional
        batch_order_option (bool): optional
        time_stamp (datetime.datetime): optional
        batch_count (int): required
    """

    TAG = enums.Tag.RequestHeader
    FIELDS = [
        ("protocol_version", enums.Tag.ProtocolVersion, SINGLE, REQUIRED),
        ("client_correlation_value", enums.Tag.ClientCorrelationValue, SINGLE, OPTIONAL),
        ("maximum_response_size", enums.Tag.MaximumResponseSize, SINGLE, OPTIONAL),
        ("asynchronous_indicator", enums.Tag.AsynchronousIndicator, SINGLE, OPTIONAL),
        ("attestation_capable_indicator", enums.Tag.AttestationCapableIndicator, SINGLE, OPTIONAL),
        ("attestation_type_list", enums.Tag.AttestationType, MULTI, OPTIONAL),
        ("authentication", enums.Tag.Authentication, SINGLE, OPTIONAL),
        ("batch_error_continuation_option", enums.Tag.BatchErrorContinuationOption, SINGLE, OPTIONAL),
        ("batch_order_option", enums.Tag.BatchOrderOption, SINGLE, OPTIONAL),
        ("time_stamp", enums.Tag.TimeStamp, SINGLE, OPTIONAL),
        ("batch_count", enums.Tag.BatchCount, SINGLE, REQUIRED)
    ]

    def __init__(self, protocol_version=None, client_correlation_value=None, maximum_response_size=None, asynchronous_indicator=None, attestation_capable_indicator=None, attestation_type_list=None, authentication=None, batch_error_continuation_option=None, batch_order_option=None, time_stamp=None, batch_count=None):
        self.protocol_version = protocol_version
        self.client_correlation_value = client_correlation_value
        self.maximum_response_size = maximum_response_size
        self.asynchronous_indicator = asynchronous_indicator
        self.attestation_capable_indicator = attestation_capable_indicator
        self.attestation_type_list = attestation_type_list
        self.authentication = authentication
        self.batch_error_continuation_option = batch_error_continuation_option
        self.batch_order_option = batch_order_option
        self.time_stamp = time_stamp
        self.batch_count = batch_count
        super(RequestHeader, self).__init__()


class RequestMessage(KmipObject):
    """
    RequestMessage holds the information of a KMIP request message.
    
    Args:
        request_header (types.RequestHeader): required
        batch_item_list (list(types.RequestBatchItem, types.ResponseBatchItem)): optional
    """

    TAG = enums.Tag.RequestMessage
    FIELDS = [
        ("request_header", enums.Tag.RequestHeader, SINGLE, REQUIRED),
        ("batch_item_list", enums.Tag.BatchItem, MULTI, MAYBE_REQUIRED)
    ]

    def __init__(self, request_header=None, batch_item_list=None):
        self.request_header = request_header
        self.batch_item_list = batch_item_list
        super(RequestMessage, self).__init__()


class ResetPasswordRequestPayload(RequestPayload):
    """
    ResetPasswordRequestPayload is the payload of a Recover Password Operation
    Request message
    
    Args:
        user_name (str): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("user_name", enums.Tag.UserName, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ResetPassword

    def __init__(self, user_name=None):
        self.user_name = user_name
        super(ResetPasswordRequestPayload, self).__init__()


class ResetPasswordResponsePayload(ResponsePayload):
    """
    ResetPasswordResponsePayload is the payload of a Recover Password Operation
    Response message.
    
    Args:
        pin (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("pin", enums.Tag.PIN, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.ResetPassword

    def __init__(self, pin=None):
        self.pin = pin
        super(ResetPasswordResponsePayload, self).__init__()


class ResponseBatchItem(KmipObject):
    """
    ResponseBatchItem holds the information of a KMIP response message batch item.
    
    Args:
        operation (enums.Operation): optional
        unique_batch_item_id (bytes): optional
        result_status (enums.ResultStatus): required
        result_reason (enums.ResultReason): optional
        result_message (str): optional
        asynchronous_correlation_value (bytes): optional
        response_payload (types.ActivateResponsePayload, types.ActivateVirtualHSMResponsePayload, types.AddAttributeResponsePayload, types.CallSEApplicationCommandResponsePayload, types.ChangePasswordResponsePayload, types.CheckResponsePayload, types.CheckSEApplicationPortAvailableResponsePayload, types.ClearSEApplicationDirectoryResponsePayload, types.ConfigureNetworkResponsePayload, types.CreateKeyPairResponsePayload, types.CreateResponsePayload, types.CreateUserResponsePayload, types.CreateVirtualHSMResponsePayload, types.DeactivateVirtualHSMResponsePayload, types.DecryptResponsePayload, types.DeleteAttributeResponsePayload, types.DeleteSEApplicationResponsePayload, types.DeleteUserResponsePayload, types.DeleteVirtualHSMResponsePayload, types.DestroyResponsePayload, types.DiscoverVersionsResponsePayload, types.EditVirtualHSMResponsePayload, types.EncryptResponsePayload, types.ExportPhysicalHSMResponsePayload, types.ExportVirtualHSMResponsePayload, types.FirmwareUpdateResponsePayload, types.GetAttributeListResponsePayload, types.GetAttributesResponsePayload, types.GetDeviceInformationResponsePayload, types.GetDeviceTimeResponsePayload, types.GetLogLevelResponsePayload, types.GetNetworkConfigurationResponsePayload, types.GetPHSMUsageResponsePayload, types.GetRequesterTypeResponsePayload, types.GetResponsePayload, types.GetSEApplicationStateResponsePayload, types.GetSEApplicationUsageResponsePayload, types.GetSEApplicationDataResponsePayload, types.GetSNMPDataResponsePayload, types.GetSystemLogResponsePayload, types.GetTLSCertificateResponsePayload, types.GetUserObjectPermissionResponsePayload, types.GetVHSMUsageResponsePayload, types.HashResponsePayload, types.ImportPhysicalHSMResponsePayload, types.ImportVirtualHSMResponsePayload, types.ListSEApplicationsResponsePayload, types.ListUsersResponsePayload, types.ListVirtualHSMsResponsePayload, types.LoadKeyResponsePayload, types.LocateResponsePayload, types.MACResponsePayload, types.MACVerifyResponsePayload, types.ModifyAttributeResponsePayload, types.OverwriteSEApplicationResponsePayload, types.QueryResponsePayload, types.RNGRetrieveResponsePayload, types.RNGSeedResponsePayload, types.ReKeyResponsePayload, types.RegisterCertificateResponsePayload, types.RegisterResponsePayload, types.RegisterSEApplicationResponsePayload, types.RemoveSEApplicationInstanceResponsePayload, types.ResetPasswordResponsePayload, types.RestartResponsePayload, types.RestartSEApplicationResponsePayload, types.RevokeResponsePayload, types.SetDateTimeResponsePayload, types.SetLogLevelResponsePayload, types.SetSNMPDataResponsePayload, types.SetUserObjectPermissionResponsePayload, types.ShutdownResponsePayload, types.SignResponsePayload, types.SignatureVerifyResponsePayload, types.StartSEApplicationResponsePayload, types.StopSEApplicationResponsePayload, types.UploadLogoImageResponsePayload): optional
        message_extension (types.MessageExtension): optional
    """

    TAG = enums.Tag.BatchItem
    FIELDS = [
        ("operation", enums.Tag.Operation, SINGLE, MAYBE_REQUIRED),
        ("unique_batch_item_id", enums.Tag.UniqueBatchItemID, SINGLE, MAYBE_REQUIRED),
        ("result_status", enums.Tag.ResultStatus, SINGLE, REQUIRED),
        ("result_reason", enums.Tag.ResultReason, SINGLE, MAYBE_REQUIRED),
        ("result_message", enums.Tag.ResultMessage, SINGLE, OPTIONAL),
        ("asynchronous_correlation_value", enums.Tag.AsynchronousCorrelationValue, SINGLE, MAYBE_REQUIRED),
        ("response_payload", enums.Tag.ResponsePayload, SINGLE, MAYBE_REQUIRED),
        ("message_extension", enums.Tag.MessageExtension, SINGLE, OPTIONAL)
    ]

    def __init__(self, operation=None, unique_batch_item_id=None, result_status=None, result_reason=None, result_message=None, asynchronous_correlation_value=None, response_payload=None, message_extension=None):
        self.operation = operation
        self.unique_batch_item_id = unique_batch_item_id
        self.result_status = result_status
        self.result_reason = result_reason
        self.result_message = result_message
        self.asynchronous_correlation_value = asynchronous_correlation_value
        self.response_payload = response_payload
        self.message_extension = message_extension
        super(ResponseBatchItem, self).__init__()


class ResponseHeader(KmipObject):
    """
    ResponseHeader holds the information of a KMIP response message header.
    
    Args:
        protocol_version (types.ProtocolVersion): required
        server_correlation_value (str): optional
        time_stamp (datetime.datetime): required
        nonce (types.Nonce): optional
        attestation_type_list (list(enums.AttestationType)): optional
        batch_count (int): required
    """

    TAG = enums.Tag.ResponseHeader
    FIELDS = [
        ("protocol_version", enums.Tag.ProtocolVersion, SINGLE, REQUIRED),
        ("server_correlation_value", enums.Tag.ServerCorrelationValue, SINGLE, OPTIONAL),
        ("time_stamp", enums.Tag.TimeStamp, SINGLE, REQUIRED),
        ("nonce", enums.Tag.Nonce, SINGLE, OPTIONAL),
        ("attestation_type_list", enums.Tag.AttestationType, MULTI, OPTIONAL),
        ("batch_count", enums.Tag.BatchCount, SINGLE, REQUIRED)
    ]

    def __init__(self, protocol_version=None, server_correlation_value=None, time_stamp=None, nonce=None, attestation_type_list=None, batch_count=None):
        self.protocol_version = protocol_version
        self.server_correlation_value = server_correlation_value
        self.time_stamp = time_stamp
        self.nonce = nonce
        self.attestation_type_list = attestation_type_list
        self.batch_count = batch_count
        super(ResponseHeader, self).__init__()


class ResponseMessage(KmipObject):
    """
    ResponseMessage holds the information of a KMIP response message.
    
    Args:
        response_header (types.ResponseHeader): required
        batch_item_list (list(types.RequestBatchItem, types.ResponseBatchItem)): optional
    """

    TAG = enums.Tag.ResponseMessage
    FIELDS = [
        ("response_header", enums.Tag.ResponseHeader, SINGLE, REQUIRED),
        ("batch_item_list", enums.Tag.BatchItem, MULTI, MAYBE_REQUIRED)
    ]

    def __init__(self, response_header=None, batch_item_list=None):
        self.response_header = response_header
        self.batch_item_list = batch_item_list
        super(ResponseMessage, self).__init__()


class RestartRequestPayload(RequestPayload):
    """
    RestartRequestPayload is the payload of a Restart Request message
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.Restart

    def __init__(self):
        super(RestartRequestPayload, self).__init__()


class RestartResponsePayload(ResponsePayload):
    """
    RestartResponsePayload is the payload of a Restart Response message
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.Restart

    def __init__(self):
        super(RestartResponsePayload, self).__init__()


class RestartSEApplicationRequestPayload(RequestPayload):
    """
    RestartSEAppRequestPayload is the payload of a Restart SE
    Application Operation Request message.
    
    Args:
        unique_identifier (str): required
        instance_identifier (str): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RestartSEApplication

    def __init__(self, unique_identifier=None, instance_identifier=None):
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        super(RestartSEApplicationRequestPayload, self).__init__()


class RestartSEApplicationResponsePayload(ResponsePayload):
    """
    RestartSEAppResponsePayload is the payload of a Restart SE
    Application Operation Response message
    
    Args:
        unique_identifier (str): required
        instance_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.RestartSEApplication

    def __init__(self, unique_identifier=None, instance_identifier=None):
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        super(RestartSEApplicationResponsePayload, self).__init__()


class RevocationReason(AttributeValue):
    """
    RevocationReason attribute is used to indicate why the Managed Cryptographic
    Object was revoked
    
    Args:
        revocation_reason_code (enums.RevocationReasonCode): required
        revocation_message (str): optional
    """

    TAG = enums.Tag.RevocationReason
    FIELDS = [
        ("revocation_reason_code", enums.Tag.RevocationReasonCode, SINGLE, REQUIRED),
        ("revocation_message", enums.Tag.RevocationMessage, SINGLE, OPTIONAL)
    ]

    def __init__(self, revocation_reason_code=None, revocation_message=None):
        self.revocation_reason_code = revocation_reason_code
        self.revocation_message = revocation_message
        super(RevocationReason, self).__init__()


class RevokeRequestPayload(RequestPayload):
    """
    RevokeRequestPayload is the payload of a Revoke Operation Request message.
    The Revoke operation SHOULD enforce special authentication and authorization
    Only the object owner or an authorized security officer SHOULD be allowed to
    issue this request.
    
    Args:
        unique_identifier (str): optional
        revocation_reason (types.RevocationReason): required
        compromise_occurrence_date (datetime.datetime): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("revocation_reason", enums.Tag.RevocationReason, SINGLE, REQUIRED),
        ("compromise_occurrence_date", enums.Tag.CompromiseOccurrenceDate, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Revoke

    def __init__(self, unique_identifier=None, revocation_reason=None, compromise_occurrence_date=None):
        self.unique_identifier = unique_identifier
        self.revocation_reason = revocation_reason
        self.compromise_occurrence_date = compromise_occurrence_date
        super(RevokeRequestPayload, self).__init__()


class RevokeResponsePayload(ResponsePayload):
    """
    RevokeResponsePayload is the payload of a Revoke Operation Response message
    
    Args:
        unique_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.Revoke

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(RevokeResponsePayload, self).__init__()


class SEApplicationData(KmipObject):
    """
    SE Application Data holds the application data.
    
    Args:
        data_path (types.DataPath): required
        data (bytes): required
    """

    TAG = enums.Tag.SEApplicationData
    FIELDS = [
        ("data_path", enums.Tag.DataPath, SINGLE, REQUIRED),
        ("data", enums.Tag.Data, SINGLE, REQUIRED)
    ]

    def __init__(self, data_path=None, data=None):
        self.data_path = data_path
        self.data = data
        super(SEApplicationData, self).__init__()


class SEApplicationInstanceUsage(KmipObject):
    """
    SEApplicationInstanceUsage holds information about a SEApp resource usage.
    
    Args:
        unique_identifier (str): required
        instance_identifier (str): required
        cpu (int): required
        ram (int): required
    """

    TAG = enums.Tag.SEApplicationInstanceUsage
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED),
        ("cpu", enums.Tag.CPU, SINGLE, REQUIRED),
        ("ram", enums.Tag.RAM, SINGLE, REQUIRED)
    ]

    def __init__(self, unique_identifier=None, instance_identifier=None, cpu=None, ram=None):
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        self.cpu = cpu
        self.ram = ram
        super(SEApplicationInstanceUsage, self).__init__()


class SEApplicationUsage(KmipObject):
    """
    SEApplicationUsage holds information about a SEApp resource usage.
    
    Args:
        unique_identifier (str): required
        usage (types.Usage): required
    """

    TAG = enums.Tag.SEApplicationUsage
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("usage", enums.Tag.Usage, SINGLE, REQUIRED)
    ]

    def __init__(self, unique_identifier=None, usage=None):
        self.unique_identifier = unique_identifier
        self.usage = usage
        super(SEApplicationUsage, self).__init__()


class SELogRequest(KmipObject):
    """
    SELogRequest holds the IID of the instance which log is being requested.
    
    Args:
        instance_identifier (str): required
    """

    TAG = enums.Tag.SELogRequest
    FIELDS = [
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED)
    ]

    def __init__(self, instance_identifier=None):
        self.instance_identifier = instance_identifier
        super(SELogRequest, self).__init__()


class SELogResponse(KmipObject):
    """
    SE Application Data holds the application data.
    
    Args:
        instance_identifier (str): required
        data (bytes): required
    """

    TAG = enums.Tag.SELogResponse
    FIELDS = [
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED),
        ("data", enums.Tag.Data, SINGLE, REQUIRED)
    ]

    def __init__(self, instance_identifier=None, data=None):
        self.instance_identifier = instance_identifier
        self.data = data
        super(SELogResponse, self).__init__()


class SecretData(ManagedObject):
    """
    SecretData contains a shared secret value that is not a key or a certificate
    (e.g., a password). The Key Block of the Secret Data contains a Key Value
    of a Secret Data Type. The Key Value MAY be wrapped.
    
    Args:
        secret_data_type (enums.SecretDataType): required
        key_block (types.KeyBlock): required
    """

    TAG = enums.Tag.SecretData
    FIELDS = [
        ("secret_data_type", enums.Tag.SecretDataType, SINGLE, REQUIRED),
        ("key_block", enums.Tag.KeyBlock, SINGLE, REQUIRED)
    ]

    def __init__(self, secret_data_type=None, key_block=None):
        self.secret_data_type = secret_data_type
        self.key_block = key_block
        super(SecretData, self).__init__()


class ServerInformation(KmipObject):
    """
    Server information struct (empty by now)
    
    Args:
    """

    TAG = enums.Tag.ServerInformation
    FIELDS = [

    ]

    def __init__(self):
        super(ServerInformation, self).__init__()


class SetDateTimeRequestPayload(RequestPayload):
    """
    SetDateTimeRequestPayload is the payload of a Set Date Time Operation Request message.
    
    Args:
        year (str): required
        month (str): required
        day (str): required
        hour (str): required
        minute (str): required
        second (str): required
        timezone (str): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("year", enums.Tag.Year, SINGLE, REQUIRED),
        ("month", enums.Tag.Month, SINGLE, REQUIRED),
        ("day", enums.Tag.Day, SINGLE, REQUIRED),
        ("hour", enums.Tag.Hour, SINGLE, REQUIRED),
        ("minute", enums.Tag.Minute, SINGLE, REQUIRED),
        ("second", enums.Tag.Second, SINGLE, REQUIRED),
        ("timezone", enums.Tag.Timezone, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.SetDateTime

    def __init__(self, year=None, month=None, day=None, hour=None, minute=None, second=None, timezone=None):
        self.year = year
        self.month = month
        self.day = day
        self.hour = hour
        self.minute = minute
        self.second = second
        self.timezone = timezone
        super(SetDateTimeRequestPayload, self).__init__()


class SetDateTimeResponsePayload(ResponsePayload):
    """
    SetDateTimeResponsePayload is the payload of a Set Date Time Operation Response message.
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.SetDateTime

    def __init__(self):
        super(SetDateTimeResponsePayload, self).__init__()


class SetLogLevelRequestPayload(RequestPayload):
    """
    SetLogLevelRequestPayload is the payload of a Set Log Level Operation Request message.
    
    Args:
        log_level (enums.LogLevel): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("log_level", enums.Tag.LogLevel, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.SetLogLevel

    def __init__(self, log_level=None):
        self.log_level = log_level
        super(SetLogLevelRequestPayload, self).__init__()


class SetLogLevelResponsePayload(ResponsePayload):
    """
    SetLogLevelResponsePayload is the payload of a Set Log Level Operation Response message.
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.SetLogLevel

    def __init__(self):
        super(SetLogLevelResponsePayload, self).__init__()


class SetSNMPDataRequestPayload(RequestPayload):
    """
    SetSNMPDataRequestPayload is the payload content of a CreateVirtualHSM
    Operation Request.
    
    Args:
        system_description (str): optional
        system_location (str): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("system_description", enums.Tag.SystemDescription, SINGLE, OPTIONAL),
        ("system_location", enums.Tag.SystemLocation, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.SetSNMPData

    def __init__(self, system_description=None, system_location=None):
        self.system_description = system_description
        self.system_location = system_location
        super(SetSNMPDataRequestPayload, self).__init__()


class SetSNMPDataResponsePayload(ResponsePayload):
    """
    SetSNMPDataResponsePayload is the payload content of a CreateVirtualHSM
    Operation Response.
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.SetSNMPData

    def __init__(self):
        super(SetSNMPDataResponsePayload, self).__init__()


class SetUserObjectPermissionRequestPayload(RequestPayload):
    """
    SetUserObjectPermissionRequestPayload is the payload of a Set User Permission to an object
    Applications Operation Request message.
    
    Args:
        unique_identifier (str): optional
        user_name (str): optional
        permission_mask (int): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("user_name", enums.Tag.UserName, SINGLE, OPTIONAL),
        ("permission_mask", enums.Tag.PermissionMask, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.SetUserObjectPermission

    def __init__(self, unique_identifier=None, user_name=None, permission_mask=None):
        self.unique_identifier = unique_identifier
        self.user_name = user_name
        self.permission_mask = permission_mask
        super(SetUserObjectPermissionRequestPayload, self).__init__()


class SetUserObjectPermissionResponsePayload(ResponsePayload):
    """
    SetUserObjectPermissionResponsePayload is the payload of a Set User Permission to an object
    Response message
    
    Args:
        unique_identifier (str): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.SetUserObjectPermission

    def __init__(self, unique_identifier=None):
        self.unique_identifier = unique_identifier
        super(SetUserObjectPermissionResponsePayload, self).__init__()


class ShutdownRequestPayload(RequestPayload):
    """
    ShutdownRequestPayload is the payload of a Shutdown Request message
    
    Args:
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.Shutdown

    def __init__(self):
        super(ShutdownRequestPayload, self).__init__()


class ShutdownResponsePayload(ResponsePayload):
    """
    ShutdownResponsePayload is the payload of a Shutdown Response message
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.Shutdown

    def __init__(self):
        super(ShutdownResponsePayload, self).__init__()


class SignRequestPayload(RequestPayload):
    """
    SignRequestPayload holds the information of a Sign Operation Request
    Payload.
    
    Args:
        unique_identifier (str): optional
        cryptographic_parameters (types.CryptographicParameters): optional
        data (bytes): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, OPTIONAL),
        ("data", enums.Tag.Data, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Sign

    def __init__(self, unique_identifier=None, cryptographic_parameters=None, data=None, correlation_value=None, init_indicator=None, final_indicator=None):
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        super(SignRequestPayload, self).__init__()


class SignResponsePayload(ResponsePayload):
    """
    SignResponsePayload holds the information of a Sign Operation Response
    Payload.
    
    Args:
        unique_identifier (str): required
        signature_data (bytes): optional
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("signature_data", enums.Tag.SignatureData, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.Sign

    def __init__(self, unique_identifier=None, signature_data=None, correlation_value=None):
        self.unique_identifier = unique_identifier
        self.signature_data = signature_data
        self.correlation_value = correlation_value
        super(SignResponsePayload, self).__init__()


class MACSignatureKeyInformation(KmipObject):
    """
    SignatureKeyInformation describes the key used for signature
    
    Args:
        unique_identifier (str): required
        cryptographic_parameters (types.CryptographicParameters): optional
    """

    TAG = enums.Tag.MACSignatureKeyInformation
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, OPTIONAL)
    ]

    def __init__(self, unique_identifier=None, cryptographic_parameters=None):
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        super(MACSignatureKeyInformation, self).__init__()


class SignatureVerifyRequestPayload(RequestPayload):
    """
    SignatureVerifyRequestPayload holds the information of a SignatureVerify
    Operation Request Payload.
    
    Args:
        unique_identifier (str): optional
        cryptographic_parameters (types.CryptographicParameters): optional
        data (bytes): optional
        signature_data (bytes): optional
        correlation_value (bytes): optional
        init_indicator (bool): optional
        final_indicator (bool): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, OPTIONAL),
        ("cryptographic_parameters", enums.Tag.CryptographicParameters, SINGLE, OPTIONAL),
        ("data", enums.Tag.Data, SINGLE, OPTIONAL),
        ("signature_data", enums.Tag.SignatureData, SINGLE, MAYBE_REQUIRED),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL),
        ("init_indicator", enums.Tag.InitIndicator, SINGLE, OPTIONAL),
        ("final_indicator", enums.Tag.FinalIndicator, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.SignatureVerify

    def __init__(self, unique_identifier=None, cryptographic_parameters=None, data=None, signature_data=None, correlation_value=None, init_indicator=None, final_indicator=None):
        self.unique_identifier = unique_identifier
        self.cryptographic_parameters = cryptographic_parameters
        self.data = data
        self.signature_data = signature_data
        self.correlation_value = correlation_value
        self.init_indicator = init_indicator
        self.final_indicator = final_indicator
        super(SignatureVerifyRequestPayload, self).__init__()


class SignatureVerifyResponsePayload(ResponsePayload):
    """
    SignatureVerifyResponsePayload holds the information of a SignatureVerify
    Operation Response Payload.
    
    Args:
        unique_identifier (str): required
        validity_indicator (enums.ValidityIndicator): required
        data (bytes): optional
        correlation_value (bytes): optional
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("validity_indicator", enums.Tag.ValidityIndicator, SINGLE, REQUIRED),
        ("data", enums.Tag.Data, SINGLE, OPTIONAL),
        ("correlation_value", enums.Tag.CorrelationValue, SINGLE, OPTIONAL)
    ]
    OPERATION = enums.Operation.SignatureVerify

    def __init__(self, unique_identifier=None, validity_indicator=None, data=None, correlation_value=None):
        self.unique_identifier = unique_identifier
        self.validity_indicator = validity_indicator
        self.data = data
        self.correlation_value = correlation_value
        super(SignatureVerifyResponsePayload, self).__init__()


class SplitKey(ManagedObject):
    """
    SplitKey is the struct to hold a part of a splitted key
    
    Args:
        split_key_parts (int): required
        key_part_identifier (int): required
        split_key_threshold (int): required
        split_key_method (enums.SplitKeyMethod): required
        prime_field_size (ttv.BigInteger): optional
        key_block (types.KeyBlock): required
    """

    TAG = enums.Tag.SplitKey
    FIELDS = [
        ("split_key_parts", enums.Tag.SplitKeyParts, SINGLE, REQUIRED),
        ("key_part_identifier", enums.Tag.KeyPartIdentifier, SINGLE, REQUIRED),
        ("split_key_threshold", enums.Tag.SplitKeyThreshold, SINGLE, REQUIRED),
        ("split_key_method", enums.Tag.SplitKeyMethod, SINGLE, REQUIRED),
        ("prime_field_size", enums.Tag.PrimeFieldSize, SINGLE, MAYBE_REQUIRED),
        ("key_block", enums.Tag.KeyBlock, SINGLE, REQUIRED)
    ]

    def __init__(self, split_key_parts=None, key_part_identifier=None, split_key_threshold=None, split_key_method=None, prime_field_size=None, key_block=None):
        self.split_key_parts = split_key_parts
        self.key_part_identifier = key_part_identifier
        self.split_key_threshold = split_key_threshold
        self.split_key_method = split_key_method
        self.prime_field_size = prime_field_size
        self.key_block = key_block
        super(SplitKey, self).__init__()


class StartSEApplicationRequestPayload(RequestPayload):
    """
    StartSEAppRequestPayload is the payload of a Start SE
    Application Operation Request message.
    
    Args:
        unique_identifier (str): required
        application_argument_list (list(str)): optional
        application_port_list (list(types.ApplicationPort)): optional
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("application_argument_list", enums.Tag.ApplicationArgument, MULTI, OPTIONAL),
        ("application_port_list", enums.Tag.ApplicationPort, MULTI, OPTIONAL)
    ]
    OPERATION = enums.Operation.StartSEApplication

    def __init__(self, unique_identifier=None, application_argument_list=None, application_port_list=None):
        self.unique_identifier = unique_identifier
        self.application_argument_list = application_argument_list
        self.application_port_list = application_port_list
        super(StartSEApplicationRequestPayload, self).__init__()


class StartSEApplicationResponsePayload(ResponsePayload):
    """
    StartSEAppResponsePayload is the payload of a Start SE
    Application Operation Response message
    
    Args:
        unique_identifier (str): required
        instance_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.StartSEApplication

    def __init__(self, unique_identifier=None, instance_identifier=None):
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        super(StartSEApplicationResponsePayload, self).__init__()


class StopSEApplicationRequestPayload(RequestPayload):
    """
    StopSEAppRequestPayload is the payload of a Stop SE Application Operation
    Request message.
    
    Args:
        unique_identifier (str): required
        instance_identifier (str): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.StopSEApplication

    def __init__(self, unique_identifier=None, instance_identifier=None):
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        super(StopSEApplicationRequestPayload, self).__init__()


class StopSEApplicationResponsePayload(ResponsePayload):
    """
    StopSEAppResponsePayload is the payload of a Stop SE Application Operation
    Response message
    
    Args:
        unique_identifier (str): required
        instance_identifier (str): required
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [
        ("unique_identifier", enums.Tag.UniqueIdentifier, SINGLE, REQUIRED),
        ("instance_identifier", enums.Tag.InstanceIdentifier, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.StopSEApplication

    def __init__(self, unique_identifier=None, instance_identifier=None):
        self.unique_identifier = unique_identifier
        self.instance_identifier = instance_identifier
        super(StopSEApplicationResponsePayload, self).__init__()


class SymmetricKey(ManagedObject):
    """
    SymmetricKey is the struct to hold a symmetric key
    
    Args:
        key_block (types.KeyBlock): required
    """

    TAG = enums.Tag.SymmetricKey
    FIELDS = [
        ("key_block", enums.Tag.KeyBlock, SINGLE, REQUIRED)
    ]

    def __init__(self, key_block=None):
        self.key_block = key_block
        super(SymmetricKey, self).__init__()


class Template(ManagedObject):
    """
    Template is deprecated as in version 1.3 and MAY be removed from subsequent
    versions of the specification. Individual Attributes SHOULD be used in
    operations which currently support use of a Template.
    
    Args:
        attribute_list (list(types.Attribute)): optional
    """

    TAG = enums.Tag.Template
    FIELDS = [
        ("attribute_list", enums.Tag.Attribute, MULTI, MAYBE_REQUIRED)
    ]

    def __init__(self, attribute_list=None):
        self.attribute_list = attribute_list
        super(Template, self).__init__()


class TemplateAttribute(KmipObject):
    """
    Template-Attribute Object structure is used to provide desired attributes
    values and/or templates template names in the request and to return the
    actual attribute values in the response
    
    Args:
        name_list (list(types.Name)): optional
        attribute_list (list(types.Attribute)): optional
    """

    TAG = enums.Tag.TemplateAttribute
    FIELDS = [
        ("name_list", enums.Tag.Name, MULTI, OPTIONAL),
        ("attribute_list", enums.Tag.Attribute, MULTI, OPTIONAL)
    ]

    def __init__(self, name_list=None, attribute_list=None):
        self.name_list = name_list
        self.attribute_list = attribute_list
        super(TemplateAttribute, self).__init__()


class TransparentDHPrivateKey(KmipObject):
    """
    TransparentDHPrivateKey holds the key material information for a DH private
    Key.
    
    Args:
        p (ttv.BigInteger): required
        q (ttv.BigInteger): optional
        g (ttv.BigInteger): required
        j (ttv.BigInteger): optional
        x (ttv.BigInteger): required
    """

    TAG = enums.Tag.KeyMaterial
    FIELDS = [
        ("p", enums.Tag.P, SINGLE, REQUIRED),
        ("q", enums.Tag.Q, SINGLE, OPTIONAL),
        ("g", enums.Tag.G, SINGLE, REQUIRED),
        ("j", enums.Tag.J, SINGLE, OPTIONAL),
        ("x", enums.Tag.X, SINGLE, REQUIRED)
    ]

    def __init__(self, p=None, q=None, g=None, j=None, x=None):
        self.p = p
        self.q = q
        self.g = g
        self.j = j
        self.x = x
        super(TransparentDHPrivateKey, self).__init__()


class TransparentDHPublicKey(KmipObject):
    """
    TransparentDHPublicKey holds the key material information for a DH public
    Key.
    
    Args:
        p (ttv.BigInteger): required
        q (ttv.BigInteger): optional
        g (ttv.BigInteger): required
        j (ttv.BigInteger): optional
        y (ttv.BigInteger): required
    """

    TAG = enums.Tag.KeyMaterial
    FIELDS = [
        ("p", enums.Tag.P, SINGLE, REQUIRED),
        ("q", enums.Tag.Q, SINGLE, OPTIONAL),
        ("g", enums.Tag.G, SINGLE, REQUIRED),
        ("j", enums.Tag.J, SINGLE, OPTIONAL),
        ("y", enums.Tag.Y, SINGLE, REQUIRED)
    ]

    def __init__(self, p=None, q=None, g=None, j=None, y=None):
        self.p = p
        self.q = q
        self.g = g
        self.j = j
        self.y = y
        super(TransparentDHPublicKey, self).__init__()


class TransparentDSAPrivateKey(KmipObject):
    """
    TransparentDSAPrivateKey holds the key material information for a DSA private
    key.
    
    Args:
        p (ttv.BigInteger): required
        q (ttv.BigInteger): required
        g (ttv.BigInteger): required
        x (ttv.BigInteger): required
    """

    TAG = enums.Tag.KeyMaterial
    FIELDS = [
        ("p", enums.Tag.P, SINGLE, REQUIRED),
        ("q", enums.Tag.Q, SINGLE, REQUIRED),
        ("g", enums.Tag.G, SINGLE, REQUIRED),
        ("x", enums.Tag.X, SINGLE, REQUIRED)
    ]

    def __init__(self, p=None, q=None, g=None, x=None):
        self.p = p
        self.q = q
        self.g = g
        self.x = x
        super(TransparentDSAPrivateKey, self).__init__()


class TransparentDSAPublicKey(KmipObject):
    """
    TransparentDSAPublicKey holds the key material information for a DSA public
    key.
    
    Args:
        p (ttv.BigInteger): required
        q (ttv.BigInteger): required
        g (ttv.BigInteger): required
        y (ttv.BigInteger): required
    """

    TAG = enums.Tag.KeyMaterial
    FIELDS = [
        ("p", enums.Tag.P, SINGLE, REQUIRED),
        ("q", enums.Tag.Q, SINGLE, REQUIRED),
        ("g", enums.Tag.G, SINGLE, REQUIRED),
        ("y", enums.Tag.Y, SINGLE, REQUIRED)
    ]

    def __init__(self, p=None, q=None, g=None, y=None):
        self.p = p
        self.q = q
        self.g = g
        self.y = y
        super(TransparentDSAPublicKey, self).__init__()


class TransparentECPrivateKey(KmipObject):
    """
    TransparentECPrivateKey holds the key material information for an EC
    private Key.
    
    Args:
        recommended_curve (enums.RecommendedCurve): required
        d (ttv.BigInteger): required
    """

    TAG = enums.Tag.KeyMaterial
    FIELDS = [
        ("recommended_curve", enums.Tag.RecommendedCurve, SINGLE, REQUIRED),
        ("d", enums.Tag.D, SINGLE, REQUIRED)
    ]

    def __init__(self, recommended_curve=None, d=None):
        self.recommended_curve = recommended_curve
        self.d = d
        super(TransparentECPrivateKey, self).__init__()


class TransparentECPublicKey(KmipObject):
    """
    TransparentECPublicKey holds the key material information for an EC
    public Key.
    
    Args:
        recommended_curve (enums.RecommendedCurve): required
        q_string (bytes): required
    """

    TAG = enums.Tag.KeyMaterial
    FIELDS = [
        ("recommended_curve", enums.Tag.RecommendedCurve, SINGLE, REQUIRED),
        ("q_string", enums.Tag.QString, SINGLE, REQUIRED)
    ]

    def __init__(self, recommended_curve=None, q_string=None):
        self.recommended_curve = recommended_curve
        self.q_string = q_string
        super(TransparentECPublicKey, self).__init__()


class TransparentRSAPrivateKey(KmipObject):
    """
    TransparentRSAPrivateKey holds the key material information for a RSA private
    Key.
    
    Args:
        modulus (ttv.BigInteger): required
        private_exponent (ttv.BigInteger): optional
        public_exponent (ttv.BigInteger): optional
        p (ttv.BigInteger): optional
        q (ttv.BigInteger): optional
        prime_exponent_p (ttv.BigInteger): optional
        prime_exponent_q (ttv.BigInteger): optional
        crt_coefficient (ttv.BigInteger): optional
    """

    TAG = enums.Tag.KeyMaterial
    FIELDS = [
        ("modulus", enums.Tag.Modulus, SINGLE, REQUIRED),
        ("private_exponent", enums.Tag.PrivateExponent, SINGLE, OPTIONAL),
        ("public_exponent", enums.Tag.PublicExponent, SINGLE, OPTIONAL),
        ("p", enums.Tag.P, SINGLE, OPTIONAL),
        ("q", enums.Tag.Q, SINGLE, OPTIONAL),
        ("prime_exponent_p", enums.Tag.PrimeExponentP, SINGLE, OPTIONAL),
        ("prime_exponent_q", enums.Tag.PrimeExponentQ, SINGLE, OPTIONAL),
        ("crt_coefficient", enums.Tag.CRTCoefficient, SINGLE, OPTIONAL)
    ]

    def __init__(self, modulus=None, private_exponent=None, public_exponent=None, p=None, q=None, prime_exponent_p=None, prime_exponent_q=None, crt_coefficient=None):
        self.modulus = modulus
        self.private_exponent = private_exponent
        self.public_exponent = public_exponent
        self.p = p
        self.q = q
        self.prime_exponent_p = prime_exponent_p
        self.prime_exponent_q = prime_exponent_q
        self.crt_coefficient = crt_coefficient
        super(TransparentRSAPrivateKey, self).__init__()


class TransparentRSAPublicKey(KmipObject):
    """
    TransparentRSAPublicKey holds the key material information for a RSA public
    Key.
    
    Args:
        modulus (ttv.BigInteger): required
        public_exponent (ttv.BigInteger): optional
    """

    TAG = enums.Tag.KeyMaterial
    FIELDS = [
        ("modulus", enums.Tag.Modulus, SINGLE, REQUIRED),
        ("public_exponent", enums.Tag.PublicExponent, SINGLE, OPTIONAL)
    ]

    def __init__(self, modulus=None, public_exponent=None):
        self.modulus = modulus
        self.public_exponent = public_exponent
        super(TransparentRSAPublicKey, self).__init__()


class TransparentSymmetricKey(KmipObject):
    """
    TransparentSymmetricKey holds the key material information for a Symmetric Key.
    
    Args:
        key (bytes): required
    """

    TAG = enums.Tag.KeyMaterial
    FIELDS = [
        ("key", enums.Tag.Key, SINGLE, REQUIRED)
    ]

    def __init__(self, key=None):
        self.key = key
        super(TransparentSymmetricKey, self).__init__()


class UploadLogoImageRequestPayload(RequestPayload):
    """
    UploadLogoImageRequestPayload is the payload of an Upload
    Logo Image Operation Request message.
    
    Args:
        image_data (bytes): required
    """

    TAG = enums.Tag.RequestPayload
    FIELDS = [
        ("image_data", enums.Tag.ImageData, SINGLE, REQUIRED)
    ]
    OPERATION = enums.Operation.UploadLogoImage

    def __init__(self, image_data=None):
        self.image_data = image_data
        super(UploadLogoImageRequestPayload, self).__init__()


class UploadLogoImageResponsePayload(ResponsePayload):
    """
    UploadLogoImageResponsePayload is the payload of an Upload
    Logo Image Operation Response message
    
    Args:
    """

    TAG = enums.Tag.ResponsePayload
    FIELDS = [

    ]
    OPERATION = enums.Operation.UploadLogoImage

    def __init__(self):
        super(UploadLogoImageResponsePayload, self).__init__()


class Usage(KmipObject):
    """
    Usage holds information about a computer resource usage.
    
    Args:
        cpu (int): required
        ram (int): required
        disk (int): required
    """

    TAG = enums.Tag.Usage
    FIELDS = [
        ("cpu", enums.Tag.CPU, SINGLE, REQUIRED),
        ("ram", enums.Tag.RAM, SINGLE, REQUIRED),
        ("disk", enums.Tag.Disk, SINGLE, REQUIRED)
    ]

    def __init__(self, cpu=None, ram=None, disk=None):
        self.cpu = cpu
        self.ram = ram
        self.disk = disk
        super(Usage, self).__init__()


class UsageLimits(AttributeValue):
    """
    Usage Limits attribute is a mechanism for limiting the usage of a Managed
    Cryptographic Object. It only applies no Managed Cryptographic Objects that
    are able to be used for applying cryptographic protection and it SHALL only
    reflect their usage for applying that protection.
    
    Args:
        usage_limits_total (ttv.LongInteger): required
        usage_limits_count (ttv.LongInteger): required
        usage_limits_unit (enums.UsageLimitsUnit): required
    """

    TAG = enums.Tag.UsageLimits
    FIELDS = [
        ("usage_limits_total", enums.Tag.UsageLimitsTotal, SINGLE, REQUIRED),
        ("usage_limits_count", enums.Tag.UsageLimitsCount, SINGLE, REQUIRED),
        ("usage_limits_unit", enums.Tag.UsageLimitsUnit, SINGLE, REQUIRED)
    ]

    def __init__(self, usage_limits_total=None, usage_limits_count=None, usage_limits_unit=None):
        self.usage_limits_total = usage_limits_total
        self.usage_limits_count = usage_limits_count
        self.usage_limits_unit = usage_limits_unit
        super(UsageLimits, self).__init__()


class UserInformation(KmipObject):
    """
    Virtual HSM Data holds information about a Virtual HSM.
    
    Args:
        user_name (str): required
        user_type (enums.UserType): required
        active (bool): required
        certificate (types.Certificate): optional
    """

    TAG = enums.Tag.UserInformation
    FIELDS = [
        ("user_name", enums.Tag.UserName, SINGLE, REQUIRED),
        ("user_type", enums.Tag.UserType, SINGLE, REQUIRED),
        ("active", enums.Tag.Active, SINGLE, REQUIRED),
        ("certificate", enums.Tag.Certificate, SINGLE, OPTIONAL)
    ]

    def __init__(self, user_name=None, user_type=None, active=None, certificate=None):
        self.user_name = user_name
        self.user_type = user_type
        self.active = active
        self.certificate = certificate
        super(UserInformation, self).__init__()


class VHSMOptions(KmipObject):
    """
    VHSM Options holds configuration parameters for a Virtual HSM.
    
    Args:
        port_range_start (int): required
        port_range_end (int): required
    """

    TAG = enums.Tag.VHSMOptions
    FIELDS = [
        ("port_range_start", enums.Tag.PortRangeStart, SINGLE, REQUIRED),
        ("port_range_end", enums.Tag.PortRangeEnd, SINGLE, REQUIRED)
    ]

    def __init__(self, port_range_start=None, port_range_end=None):
        self.port_range_start = port_range_start
        self.port_range_end = port_range_end
        super(VHSMOptions, self).__init__()


class VHSMUsage(KmipObject):
    """
    Usage holds information about a VHSM resource usage.
    
    Args:
        vhsm_unique_id (int): required
        usage (types.Usage): required
    """

    TAG = enums.Tag.VHSMUsage
    FIELDS = [
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, REQUIRED),
        ("usage", enums.Tag.Usage, SINGLE, REQUIRED)
    ]

    def __init__(self, vhsm_unique_id=None, usage=None):
        self.vhsm_unique_id = vhsm_unique_id
        self.usage = usage
        super(VHSMUsage, self).__init__()


class ValidationInformation(KmipObject):
    """
    Validation Information base object contains details of a formal validation.
    
    Args:
        validation_authority_type (enums.ValidationAuthorityType): required
        validation_authority_country (str): optional
        validation_authority_uri (str): optional
        validation_version_major (int): required
        validation_version_minor (int): optional
        validation_type (enums.ValidationType): required
        validation_level (int): required
        validation_certificate_identifier (str): optional
        validation_certificate_uri (str): optional
        validation_vendor_uri (str): optional
        validation_profile_list (list(str)): optional
    """

    TAG = enums.Tag.ValidationInformation
    FIELDS = [
        ("validation_authority_type", enums.Tag.ValidationAuthorityType, SINGLE, REQUIRED),
        ("validation_authority_country", enums.Tag.ValidationAuthorityCountry, SINGLE, OPTIONAL),
        ("validation_authority_uri", enums.Tag.ValidationAuthorityURI, SINGLE, OPTIONAL),
        ("validation_version_major", enums.Tag.ValidationVersionMajor, SINGLE, REQUIRED),
        ("validation_version_minor", enums.Tag.ValidationVersionMinor, SINGLE, OPTIONAL),
        ("validation_type", enums.Tag.ValidationType, SINGLE, REQUIRED),
        ("validation_level", enums.Tag.ValidationLevel, SINGLE, REQUIRED),
        ("validation_certificate_identifier", enums.Tag.ValidationCertificateIdentifier, SINGLE, OPTIONAL),
        ("validation_certificate_uri", enums.Tag.ValidationCertificateURI, SINGLE, OPTIONAL),
        ("validation_vendor_uri", enums.Tag.ValidationVendorURI, SINGLE, OPTIONAL),
        ("validation_profile_list", enums.Tag.ValidationProfile, MULTI, OPTIONAL)
    ]

    def __init__(self, validation_authority_type=None, validation_authority_country=None, validation_authority_uri=None, validation_version_major=None, validation_version_minor=None, validation_type=None, validation_level=None, validation_certificate_identifier=None, validation_certificate_uri=None, validation_vendor_uri=None, validation_profile_list=None):
        self.validation_authority_type = validation_authority_type
        self.validation_authority_country = validation_authority_country
        self.validation_authority_uri = validation_authority_uri
        self.validation_version_major = validation_version_major
        self.validation_version_minor = validation_version_minor
        self.validation_type = validation_type
        self.validation_level = validation_level
        self.validation_certificate_identifier = validation_certificate_identifier
        self.validation_certificate_uri = validation_certificate_uri
        self.validation_vendor_uri = validation_vendor_uri
        self.validation_profile_list = validation_profile_list
        super(ValidationInformation, self).__init__()


class Version(KmipObject):
    """
    Version holds information about of the device version.
    
    Args:
        major (int): required
        minor (int): required
        patch (int): required
    """

    TAG = enums.Tag.Version
    FIELDS = [
        ("major", enums.Tag.Major, SINGLE, REQUIRED),
        ("minor", enums.Tag.Minor, SINGLE, REQUIRED),
        ("patch", enums.Tag.Patch, SINGLE, REQUIRED)
    ]

    def __init__(self, major=None, minor=None, patch=None):
        self.major = major
        self.minor = minor
        self.patch = patch
        super(Version, self).__init__()


class VirtualHSMData(KmipObject):
    """
    Virtual HSM Data holds information about a Virtual HSM.
    
    Args:
        vhsm_unique_id (int): required
        active (bool): required
        ttlv_port (int): required
        https_port (int): required
        port_range_start (int): optional
        port_range_end (int): optional
    """

    TAG = enums.Tag.VirtualHSMData
    FIELDS = [
        ("vhsm_unique_id", enums.Tag.VHSMUniqueID, SINGLE, REQUIRED),
        ("active", enums.Tag.Active, SINGLE, REQUIRED),
        ("ttlv_port", enums.Tag.TTLVPort, SINGLE, REQUIRED),
        ("https_port", enums.Tag.HTTPSPort, SINGLE, REQUIRED),
        ("port_range_start", enums.Tag.PortRangeStart, SINGLE, OPTIONAL),
        ("port_range_end", enums.Tag.PortRangeEnd, SINGLE, OPTIONAL)
    ]

    def __init__(self, vhsm_unique_id=None, active=None, ttlv_port=None, https_port=None, port_range_start=None, port_range_end=None):
        self.vhsm_unique_id = vhsm_unique_id
        self.active = active
        self.ttlv_port = ttlv_port
        self.https_port = https_port
        self.port_range_start = port_range_start
        self.port_range_end = port_range_end
        super(VirtualHSMData, self).__init__()


class X_509CertificateIdentifier(AttributeValue):
    """
    X_509CertificateIdentifier is a struct used to provide the identification of
    an X_509 public key certificate.
    
    Args:
        issuer_distinguished_name (bytes): required
        certificate_serial_number (bytes): required
    """

    TAG = enums.Tag.X_509CertificateIdentifier
    FIELDS = [
        ("issuer_distinguished_name", enums.Tag.IssuerDistinguishedName, SINGLE, REQUIRED),
        ("certificate_serial_number", enums.Tag.CertificateSerialNumber, SINGLE, REQUIRED)
    ]

    def __init__(self, issuer_distinguished_name=None, certificate_serial_number=None):
        self.issuer_distinguished_name = issuer_distinguished_name
        self.certificate_serial_number = certificate_serial_number
        super(X_509CertificateIdentifier, self).__init__()


class X_509CertificateIssuer(AttributeValue):
    """
    X_509CertificateIssuer is a structure used to identify the issuer of a
    X.509 certificate,
    
    Args:
        issuer_distinguished_name (bytes): optional
        issuer_alternative_name_list (list(bytes)): optional
    """

    TAG = enums.Tag.X_509CertificateIssuer
    FIELDS = [
        ("issuer_distinguished_name", enums.Tag.IssuerDistinguishedName, SINGLE, MAYBE_REQUIRED),
        ("issuer_alternative_name_list", enums.Tag.IssuerAlternativeName, MULTI, OPTIONAL)
    ]

    def __init__(self, issuer_distinguished_name=None, issuer_alternative_name_list=None):
        self.issuer_distinguished_name = issuer_distinguished_name
        self.issuer_alternative_name_list = issuer_alternative_name_list
        super(X_509CertificateIssuer, self).__init__()


class X_509CertificateSubject(AttributeValue):
    """
    X_509CertificateSubject is a structure used to identify the subject of a
    X.509 certificate.
    
    Args:
        subject_distinguished_name (bytes): optional
        subject_alternative_name_list (list(bytes)): optional
    """

    TAG = enums.Tag.X_509CertificateSubject
    FIELDS = [
        ("subject_distinguished_name", enums.Tag.SubjectDistinguishedName, SINGLE, MAYBE_REQUIRED),
        ("subject_alternative_name_list", enums.Tag.SubjectAlternativeName, MULTI, MAYBE_REQUIRED)
    ]

    def __init__(self, subject_distinguished_name=None, subject_alternative_name_list=None):
        self.subject_distinguished_name = subject_distinguished_name
        self.subject_alternative_name_list = subject_alternative_name_list
        super(X_509CertificateSubject, self).__init__()


class CommonTemplateAttribute(TemplateAttribute):
    """
    CommonTemplateAttribute Object structure specifies desired attributes in
    templates and/or as individual attributes to be associated with the new
    object that apply to both the Private and Public Key Objects.
        """

    TAG = enums.Tag.CommonTemplateAttribute


class PrivateKeyTemplateAttribute(TemplateAttribute):
    """
    PrivateKeyTemplateAttribute Object structure specifies templates and/or
    attributes to be associated with the new object that apply to the Private Key
    Object.
        """

    TAG = enums.Tag.PrivateKeyTemplateAttribute


class PublicKeyTemplateAttribute(TemplateAttribute):
    """
    PublicKeyTemplateAttribute Object structure specifies templates and/or
    attributes to be associated with the new object that apply to the Public Key
    Object.
        """

    TAG = enums.Tag.PublicKeyTemplateAttribute


class TransparentECDSAPrivateKey(TransparentECPrivateKey):
    """
    TransparentECDSAPrivateKey holds the key material information for an ECSA
    private Key.
        """

    TAG = enums.Tag.KeyMaterial


class TransparentECDSAPublicKey(TransparentECPublicKey):
    """
    TransparentECDSAPublicKey holds the key material information for an ECDSA
    public Key.
        """

    TAG = enums.Tag.KeyMaterial


class TransparentECDSPrivateKey(TransparentECPrivateKey):
    """
    TransparentECDSPrivateKey holds the key material information for an ECDS
    private Key.
        """

    TAG = enums.Tag.KeyMaterial


class TransparentECDSPublicKey(TransparentECPublicKey):
    """
    TransparentECDSPublicKey holds the key material information for an ECDS
    public Key.
        """

    TAG = enums.Tag.KeyMaterial


class TransparentECMQVPrivateKey(TransparentECPrivateKey):
    """
    TransparentECMQVPrivateKey holds the key material information for an ECMQV
    private Key.
        """

    TAG = enums.Tag.KeyMaterial


class TransparentECMQVPublicKey(TransparentECPublicKey):
    """
    TransparentECMQVPublicKey holds the key material information for an ECMQV
    public Key.
        """

    TAG = enums.Tag.KeyMaterial


__all__ += ['ActivateRequestPayload', 'ActivateResponsePayload', 'ActivateVirtualHSMRequestPayload', 'ActivateVirtualHSMResponsePayload', 'AddAttributeRequestPayload', 'AddAttributeResponsePayload', 'AlternativeName', 'ApplicationBasicInfo', 'ApplicationInstanceInfo', 'ApplicationPort', 'ApplicationSpecificInformation', 'AttestationCredential', 'Attribute', 'Authentication', 'CallSEApplicationCommandRequestPayload', 'CallSEApplicationCommandResponsePayload', 'CapabilityInformation', 'Certificate', 'CertificateIdentifier', 'CertificateIssuer', 'CertificateSubject', 'ChangePasswordRequestPayload', 'ChangePasswordResponsePayload', 'CheckRequestPayload', 'CheckResponsePayload', 'CheckSEApplicationPortAvailableRequestPayload', 'CheckSEApplicationPortAvailableResponsePayload', 'ClearSEApplicationDirectoryRequestPayload', 'ClearSEApplicationDirectoryResponsePayload', 'ConfigureNetworkRequestPayload', 'ConfigureNetworkResponsePayload', 'CreateKeyPairRequestPayload', 'CreateKeyPairResponsePayload', 'CreateRequestPayload', 'CreateResponsePayload', 'CreateUserRequestPayload', 'CreateUserResponsePayload', 'CreateVirtualHSMRequestPayload', 'CreateVirtualHSMResponsePayload', 'Credential', 'CryptographicDomainParameters', 'CryptographicParameters', 'DataPath', 'DeactivateVirtualHSMRequestPayload', 'DeactivateVirtualHSMResponsePayload', 'DecryptRequestPayload', 'DecryptResponsePayload', 'DeleteAttributeRequestPayload', 'DeleteAttributeResponsePayload', 'DeleteSEApplicationRequestPayload', 'DeleteSEApplicationResponsePayload', 'DeleteUserRequestPayload', 'DeleteUserResponsePayload', 'DeleteVirtualHSMRequestPayload', 'DeleteVirtualHSMResponsePayload', 'DestroyRequestPayload', 'DestroyResponsePayload', 'DeviceCredential', 'DeviceStatus', 'Digest', 'DiscoverVersionsRequestPayload', 'DiscoverVersionsResponsePayload', 'EditVirtualHSMRequestPayload', 'EditVirtualHSMResponsePayload', 'EncryptRequestPayload', 'EncryptResponsePayload', 'EncryptionKeyInformation', 'ExportPhysicalHSMRequestPayload', 'ExportPhysicalHSMResponsePayload', 'ExportVirtualHSMRequestPayload', 'ExportVirtualHSMResponsePayload', 'ExtensionInformation', 'FirmwareUpdateRequestPayload', 'FirmwareUpdateResponsePayload', 'GetAttributeListRequestPayload', 'GetAttributeListResponsePayload', 'GetAttributesRequestPayload', 'GetAttributesResponsePayload', 'GetDeviceInformationRequestPayload', 'GetDeviceInformationResponsePayload', 'GetDeviceTimeRequestPayload', 'GetDeviceTimeResponsePayload', 'GetLogLevelRequestPayload', 'GetLogLevelResponsePayload', 'GetNetworkConfigurationRequestPayload', 'GetNetworkConfigurationResponsePayload', 'GetPHSMUsageRequestPayload', 'GetPHSMUsageResponsePayload', 'GetRequestPayload', 'GetRequesterTypeRequestPayload', 'GetRequesterTypeResponsePayload', 'GetResponsePayload', 'GetSEApplicationStateRequestPayload', 'GetSEApplicationStateResponsePayload', 'GetSEApplicationUsageRequestPayload', 'GetSEApplicationUsageResponsePayload', 'GetSEApplicationDataRequestPayload', 'GetSEApplicationDataResponsePayload', 'GetSNMPDataRequestPayload', 'GetSNMPDataResponsePayload', 'GetSystemLogRequestPayload', 'GetSystemLogResponsePayload', 'GetTLSCertificateRequestPayload', 'GetTLSCertificateResponsePayload', 'GetUserObjectPermissionRequestPayload', 'GetUserObjectPermissionResponsePayload', 'GetVHSMUsageRequestPayload', 'GetVHSMUsageResponsePayload', 'HashRequestPayload', 'HashResponsePayload', 'ImportPhysicalHSMRequestPayload', 'ImportPhysicalHSMResponsePayload', 'ImportVirtualHSMRequestPayload', 'ImportVirtualHSMResponsePayload', 'KeyBlock', 'KeyValueLocation', 'KeyValue', 'KeyWrappingData', 'KeyWrappingSpecification', 'LanInterfaceInformation', 'Link', 'ListSEApplicationsRequestPayload', 'ListSEApplicationsResponsePayload', 'ListUsersRequestPayload', 'ListUsersResponsePayload', 'ListVirtualHSMsRequestPayload', 'ListVirtualHSMsResponsePayload', 'LoadKeyRequestPayload', 'LoadKeyResponsePayload', 'LocateRequestPayload', 'LocateResponsePayload', 'MACRequestPayload', 'MACResponsePayload', 'MACVerifyRequestPayload', 'MACVerifyResponsePayload', 'MessageExtension', 'ModifyAttributeRequestPayload', 'ModifyAttributeResponsePayload', 'Name', 'Nonce', 'OpaqueObject', 'OverwriteSEApplicationRequestPayload', 'OverwriteSEApplicationResponsePayload', 'PGPKey', 'PasswordCredential', 'PrivateKey', 'ProfileInformation', 'ProtocolVersion', 'PublicKey', 'QueryRequestPayload', 'QueryResponsePayload', 'RNGParameters', 'RNGRetrieveRequestPayload', 'RNGRetrieveResponsePayload', 'RNGSeedRequestPayload', 'RNGSeedResponsePayload', 'ReKeyRequestPayload', 'ReKeyResponsePayload', 'RegisterCertificateRequestPayload', 'RegisterCertificateResponsePayload', 'RegisterRequestPayload', 'RegisterResponsePayload', 'RegisterSEApplicationRequestPayload', 'RegisterSEApplicationResponsePayload', 'RemoveSEApplicationInstanceRequestPayload', 'RemoveSEApplicationInstanceResponsePayload', 'RequestBatchItem', 'RequestHeader', 'RequestMessage', 'ResetPasswordRequestPayload', 'ResetPasswordResponsePayload', 'ResponseBatchItem', 'ResponseHeader', 'ResponseMessage', 'RestartRequestPayload', 'RestartResponsePayload', 'RestartSEApplicationRequestPayload', 'RestartSEApplicationResponsePayload', 'RevocationReason', 'RevokeRequestPayload', 'RevokeResponsePayload', 'SEApplicationData', 'SEApplicationInstanceUsage', 'SEApplicationUsage', 'SELogRequest', 'SELogResponse', 'SecretData', 'ServerInformation', 'SetDateTimeRequestPayload', 'SetDateTimeResponsePayload', 'SetLogLevelRequestPayload', 'SetLogLevelResponsePayload', 'SetSNMPDataRequestPayload', 'SetSNMPDataResponsePayload', 'SetUserObjectPermissionRequestPayload', 'SetUserObjectPermissionResponsePayload', 'ShutdownRequestPayload', 'ShutdownResponsePayload', 'SignRequestPayload', 'SignResponsePayload', 'MACSignatureKeyInformation', 'SignatureVerifyRequestPayload', 'SignatureVerifyResponsePayload', 'SplitKey', 'StartSEApplicationRequestPayload', 'StartSEApplicationResponsePayload', 'StopSEApplicationRequestPayload', 'StopSEApplicationResponsePayload', 'SymmetricKey', 'Template', 'TemplateAttribute', 'TransparentDHPrivateKey', 'TransparentDHPublicKey', 'TransparentDSAPrivateKey', 'TransparentDSAPublicKey', 'TransparentECPrivateKey', 'TransparentECPublicKey', 'TransparentRSAPrivateKey', 'TransparentRSAPublicKey', 'TransparentSymmetricKey', 'UploadLogoImageRequestPayload', 'UploadLogoImageResponsePayload', 'Usage', 'UsageLimits', 'UserInformation', 'VHSMOptions', 'VHSMUsage', 'ValidationInformation', 'Version', 'VirtualHSMData', 'X_509CertificateIdentifier', 'X_509CertificateIssuer', 'X_509CertificateSubject', 'CommonTemplateAttribute', 'PrivateKeyTemplateAttribute', 'PublicKeyTemplateAttribute', 'TransparentECDSAPrivateKey', 'TransparentECDSAPublicKey', 'TransparentECDSPrivateKey', 'TransparentECDSPublicKey', 'TransparentECMQVPrivateKey', 'TransparentECMQVPublicKey']
