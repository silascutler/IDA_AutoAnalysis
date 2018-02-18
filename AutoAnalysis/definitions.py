#!/usr/bin/env python

PEAPIs = {}

PEAPIs['Registry'] = { 'flag': 'R', 'calls' : [ "GetSystemRegistryQuota", "RegCloseKey", "RegConnectRegistry", "RegCopyTree", "RegCreateKeyEx", "RegCreateKeyTransacted", "RegDeleteKey", "RegDeleteKeyEx", "RegDeleteKeyTransacted", "RegDeleteKeyValue", "RegDeleteTree", "RegDeleteValue", "RegDisablePredefinedCache", "RegDisablePredefinedCacheEx", "RegDisableReflectionKey", "RegEnableReflectionKey", "RegEnumKeyEx", "RegEnumValue", "RegFlushKey", "RegGetKeySecurity", "RegGetValue", "RegLoadKey", "RegLoadMUIString", "RegNotifyChangeKeyValue", "RegOpenCurrentUser", "RegOpenKeyEx", "RegOpenKeyTransacted", "RegOpenUserClassesRoot", "RegOverridePredefKey", "RegQueryInfoKey", "RegQueryMultipleValues", "RegQueryReflectionKey", "RegQueryValueEx", 'RegQueryValueExW' "RegReplaceKey", "RegRestoreKey", "RegSaveKey", "RegSaveKeyEx", "RegSetKeyValue", "RegSetKeySecurity", "RegSetValueEx", "RegUnLoadKey"]}
PEAPIs['Files'] = { 'flag': 'F', 'calls' : ["AddUsersToEncryptedFile", "AreFileApisANSI", "CancelIo", "CancelIoEx", "CancelSynchronousIo", "CheckNameLegalDOS8Dot3", "CloseEncryptedFileRaw", "CopyFile", "CopyFile2", "CopyFile2ProgressRoutine", "CopyFileEx", "CopyFileTransacted", "CopyProgressRoutine", "CreateFile", "CreateFile2", "CreateFileTransacted", "CreateHardLink", "CreateHardLinkTransacted", "CreateIoCompletionPort", "CreateSymbolicLink", "CreateSymbolicLinkTransacted", "DecryptFile", "DeleteFile", "DeleteFileTransacted", "DuplicateEncryptionInfoFile", "EncryptFile", "EncryptionDisable", "ExportCallback", "FileEncryptionStatus", "FileIOCompletionRoutine", "FindClose", "FindFirstFile", "FindFirstFileEx", "FindFirstFileNameTransactedW", "FindFirstFileNameW", "FindFirstFileTransacted", "FindFirstStreamTransactedW", "FindFirstStreamW", "FindNextFile", "FindNextFileNameW", "FindNextStreamW", "FlushFileBuffers", "FreeEncryptionCertificateHashList", "GetBinaryType", "GetCompressedFileSize", "GetCompressedFileSizeTransacted", "GetExpandedName", "GetFileAttributes", "GetFileAttributesEx", "GetFileAttributesTransacted", "GetFileBandwidthReservation", "GetFileInformationByHandle", "GetFileInformationByHandleEx", "GetFileSize", "GetFileSizeEx", "GetFileType", "GetFinalPathNameByHandle", "GetFullPathName", "GetFullPathNameTransacted", "GetLongPathName", "GetLongPathNameTransacted", "GetQueuedCompletionStatus", "GetQueuedCompletionStatusEx", "GetShortPathName", "GetTempFileName", "GetTempPath", "ImportCallback", "LockFile", "LockFileEx", "LZClose", "LZCopy", "LZInit", "LZOpenFile", "LZRead", "LZSeek", "MoveFile", "MoveFileEx", "MoveFileTransacted", "MoveFileWithProgress", "OpenEncryptedFileRaw", "OpenFile", "OpenFileById", "PostQueuedCompletionStatus", "QueryRecoveryAgentsOnEncryptedFile", "QueryUsersOnEncryptedFile", "ReadEncryptedFileRaw", "ReadFile", "ReadFileEx", "ReadFileScatter", "RemoveUsersFromEncryptedFile", "ReOpenFile", "ReplaceFile", "SearchPath", "SetEndOfFile", "SetFileApisToANSI", "SetFileApisToOEM", "SetFileAttributes", "SetFileAttributesTransacted", "SetFileBandwidthReservation", "SetFileCompletionNotificationModes", "SetFileInformationByHandle", "SetFileIoOverlappedRange", "SetFilePointer", "SetFilePointerEx", "SetFileShortName", "SetFileValidData", "SetSearchPathMode", "SetUserFileEncryptionKey", "UnlockFile", "UnlockFileEx", "WofEnumEntries", "WofEnumEntryProc", "WofEnumFilesProc", "WofFileEnumFiles", "WofGetDriverVersion", "WofIsExternalFile", "WofSetFileDataLocation", "WofShouldCompressBinaries", "WofWimAddEntry", "WofWimEnumFiles", "WofWimRemoveEntry", "WofWimSuspendEntry", "WofWimUpdateEntry", "Wow64DisableWow64FsRedirection", "Wow64EnableWow64FsRedirection", "Wow64RevertWow64FsRedirection", "WriteEncryptedFileRaw", "WriteFile", "WriteFileEx", "WriteFileGather"]}
PEAPIs['User'] = { 'flag': 'U', 'calls' :  [ "NetUserAdd", "NetUserChangePassword", "NetUserDel", "NetUserEnum", "NetUserGetGroups", "NetUserGetInfo", "NetUserGetLocalGroups", "NetUserSetGroups", "NetUserSetInfo"]}
PEAPIs['Socket'] = { 'flag': 'S', 'calls' : ["accept", "AcceptEx", "bind", "closesocket", "connect", "ConnectEx", "DisconnectEx", "EnumProtocols", "freeaddrinfo", "FreeAddrInfoEx", "FreeAddrInfoW", "gai_strerror", "GetAcceptExSockaddrs", "GetAddressByName", "getaddrinfo", "GetAddrInfoEx", "GetAddrInfoExCancel", "GetAddrInfoExOverlappedResult", "GetAddrInfoW", "gethostbyaddr", "gethostbyname", "gethostname", "GetHostNameW", "getipv4sourcefilter", "GetNameByType", "getnameinfo", "GetNameInfoW", "getpeername", "getprotobyname", "getprotobynumber", "getservbyname", "getservbyport", "GetService", "getsockname", "getsockopt", "getsourcefilter", "GetTypeByName", "htond", "htonf", "htonl", "htonll", "htons", "inet_addr", "inet_ntoa", "InetNtop", "InetPton", "ioctlsocket", "listen", "ntohd", "ntohf", "ntohl", "ntohll", "ntohs", "recv", "recvfrom", "RIOCloseCompletionQueue", "RIOCreateCompletionQueue", "RIOCreateRequestQueue", "RIODequeueCompletion", "RIODeregisterBuffer", "RIONotify", "RIOReceive", "RIOReceiveEx", "RIORegisterBuffer", "RIOResizeCompletionQueue", "RIOResizeRequestQueue", "RIOSend", "RIOSendEx", "select", "send", "sendto", "SetAddrInfoEx", "setipv4sourcefilter", "SetService", "SetSocketMediaStreamingMode", "setsockopt", "setsourcefilter", "shutdown", "socket", "TransmitFile", "TransmitPackets", "WSAAccept", "WSAAddressToString", "WSAAsyncGetHostByAddr", "WSAAsyncGetHostByName", "WSAAsyncGetProtoByName", "WSAAsyncGetProtoByNumber", "WSAAsyncGetServByName", "WSAAsyncGetServByPort", "WSAAsyncSelect", "WSACancelAsyncRequest", "WSACleanup", "WSACloseEvent", "WSAConnect", "WSAConnectByList", "WSAConnectByName", "WSACreateEvent", "WSADeleteSocketPeerTargetName", "WSADuplicateSocket", "WSAEnumNameSpaceProviders", "WSAEnumNameSpaceProvidersEx", "WSAEnumNetworkEvents", "WSAEnumProtocols", "WSAEventSelect", "__WSAFDIsSet", "WSAGetLastError", "WSAGetOverlappedResult", "WSAGetQOSByName", "WSAGetServiceClassInfo", "WSAGetServiceClassNameByClassId", "WSAHtonl", "WSAHtons", "WSAImpersonateSocketPeer", "WSAInstallServiceClass", "WSAIoctl", "WSAJoinLeaf", "WSALookupServiceBegin", "WSALookupServiceEnd", "WSALookupServiceNext", "WSANSPIoctl", "WSANtohl", "WSANtohs", "WSAPoll", "WSAProviderConfigChange", "WSAQuerySocketSecurity", "WSARecv", "WSARecvDisconnect", "WSARecvEx", "WSARecvFrom", "WSARecvMsg", "WSARemoveServiceClass", "WSAResetEvent", "WSARevertImpersonation", "WSASend", "WSASendDisconnect", "WSASendMsg", "WSASendTo", "WSASetEvent", "WSASetLastError", "WSASetService", "WSASetSocketPeerTargetName", "WSASetSocketSecurity", "WSASocket", "WSAStartup", "WSAStringToAddress", "WSAWaitForMultipleEvents"]}
PEAPIs['Crypto'] = { 'flag': 'C', 'calls' : ["A_SHAFinal", "A_SHAInit", "A_SHAUpdate", "CertAddCertificateContextToStore", "CertAddCertificateLinkToStore", "CertAddCRLContextToStore", "CertAddCRLLinkToStore", "CertAddCTLContextToStore", "CertAddCTLLinkToStore", "CertAddEncodedCertificateToStore", "CertAddEncodedCRLToStore", "CertAddEncodedCTLToStore", "CertAddEnhancedKeyUsageIdentifier", "CertAddRefServerOcspResponse", "CertAddRefServerOcspResponseContext", "CertAddSerializedElementToStore", "CertAddStoreToCollection", "CertAlgIdToOID", "CertCloseServerOcspResponse", "CertCloseStore", "CertCompareCertificate", "CertCompareCertificateName", "CertCompareIntegerBlob", "CertComparePublicKeyInfo", "CertControlStore", "CertCreateCertificateChainEngine", "CertCreateCertificateContext", "CertCreateContext", "CertCreateCRLContext", "CertCreateCTLContext", "CertCreateCTLEntryFromCertificateContextProperties", "CertCreateSelfSignCertificate", "CertDeleteCertificateFromStore", "CertDeleteCRLFromStore", "CertDeleteCTLFromStore", "CertDuplicateCertificateChain", "CertDuplicateCertificateContext", "CertDuplicateCRLContext", "CertDuplicateCTLContext", "CertDuplicateStore", "CertEnumCertificateContextProperties", "CertEnumCertificatesInStore", "CertEnumCRLContextProperties", "CertEnumCRLsInStore", "CertEnumCTLContextProperties", "CertEnumCTLsInStore", "CertEnumPhysicalStore", "CertEnumSubjectInSortedCTL", "CertEnumSystemStore", "CertEnumSystemStoreLocation", "CertFindAttribute", "CertFindCertificateInCRL", "CertFindCertificateInStore", "CertFindChainInStore", "CertFindCRLInStore", "CertFindCTLInStore", "CertFindExtension", "CertFindRDNAttr", "CertFindSubjectInCTL", "CertFindSubjectInSortedCTL", "CertFreeCertificateChain", "CertFreeCertificateChainEngine", "CertFreeCertificateChainList", "CertFreeCertificateContext", "CertFreeCRLContext", "CertFreeCTLContext", "CertGetCertificateChain", "CertGetCertificateContextProperty", "CertGetCRLContextProperty", "CertGetCRLFromStore", "CertGetCTLContextProperty", "CertGetEnhancedKeyUsage", "CertGetIntendedKeyUsage", "CertGetIssuerCertificateFromStore", "CertGetNameString", "CertGetPublicKeyLength", "CertGetServerOcspResponseContext", "CertGetStoreProperty", "CertGetSubjectCertificateFromStore", "CertGetValidUsages", "CertIsRDNAttrsInCertificateName", "CertIsStrongHashToSign", "CertIsValidCRLForCertificate", "CertModifyCertificatesToTrust", "CertNameToStr", "CertOIDToAlgId", "CertOpenServerOcspResponse", "CertOpenStore", "CertOpenSystemStore", "CertRDNValueToStr", "CertRegisterPhysicalStore", "CertRegisterSystemStore", "CertRemoveEnhancedKeyUsageIdentifier", "CertRemoveStoreFromCollection", "CertRetrieveLogoOrBiometricInfo", "CertSaveStore", "CertSelectCertificate", "CertSelectCertificateChains", "CertSelectionGetSerializedBlob", "CertSerializeCertificateStoreElement", "CertSerializeCRLStoreElement", "CertSerializeCTLStoreElement", "CertSetCertificateContextPropertiesFromCTLEntry", "CertSetCertificateContextProperty", "CertSetCRLContextProperty", "CertSetCTLContextProperty", "CertSetEnhancedKeyUsage", "CertSetStoreProperty", "CertStrToName", "CertUnregisterPhysicalStore", "CertUnregisterSystemStore", "CertVerifyCertificateChainPolicy", "CertVerifyCRLRevocation", "CertVerifyCRLTimeValidity", "CertVerifyCTLUsage", "CertVerifyRevocation", "CertVerifySubjectCertificateContext", "CertVerifyTimeValidity", "CertVerifyValidityNesting", "CryptAcquireContext", "CryptBinaryToString", "CryptContextAddRef", "CryptCreateHash", "CryptCreateKeyIdentifierFromCSP", "CryptDecodeMessage", "CryptDecodeObject", "CryptDecodeObjectEx", "CryptDecrypt", "CryptDecryptAndVerifyMessageSignature", "CryptDecryptMessage", "CryptDeriveKey", "CryptDestroyHash", "CryptDestroyKey", "CryptDuplicateHash", "CryptDuplicateKey", "CryptEncodeObject", "CryptEncodeObjectEx", "CryptEncrypt", "CryptEncryptMessage", "CryptEnumKeyIdentifierProperties", "CryptEnumProviders", "CryptEnumProviderTypes", "CryptExportKey", "CryptExportPKCS8", "CryptExportPKCS8Ex", "CryptExportPublicKeyInfo", "CryptExportPublicKeyInfoEx", "CryptExportPublicKeyInfoFromBCryptKeyHandle", "CryptFindCertificateKeyProvInfo", "CryptFindLocalizedName", "CryptFormatObject", "CryptGenKey", "CryptGenRandom", "CryptGetDefaultProvider", "CryptGetHashParam", "CryptGetKeyIdentifierProperty", "CryptGetKeyParam", "CryptGetMessageCertificates", "CryptGetMessageSignerCount", "CryptGetProvParam", "CryptGetUserKey", "CryptHashCertificate", "CryptHashCertificate2", "CryptHashData", "CryptHashMessage", "CryptHashPublicKeyInfo", "CryptHashSessionKey", "CryptHashToBeSigned", "CryptImportKey", "CryptImportPKCS8", "CryptImportPublicKeyInfo", "CryptImportPublicKeyInfoEx", "CryptImportPublicKeyInfoEx2", "CryptInstallDefaultContext", "CryptMemAlloc", "CryptMemFree", "CryptMemRealloc", "CryptMsgCalculateEncodedLength", "CryptMsgClose", "CryptMsgControl", "CryptMsgCountersign", "CryptMsgCountersignEncoded", "CryptMsgDuplicate", "CryptMsgEncodeAndSignCTL", "CryptMsgGetAndVerifySigner", "CryptMsgGetParam", "CryptMsgOpenToDecode", "CryptMsgOpenToEncode", "CryptMsgSignCTL", "CryptMsgUpdate", "CryptMsgVerifyCountersignatureEncoded", "CryptMsgVerifyCountersignatureEncodedEx", "CryptProtectData", "CryptProtectMemory", "CryptQueryObject", "CryptReleaseContext", "CryptSetHashParam", "CryptSetKeyIdentifierProperty", "CryptSetKeyParam", "CryptSetProvParam", "CryptSignAndEncodeCertificate", "CryptSignAndEncryptMessage", "CryptSignCertificate", "CryptSignHash", "CryptSignMessage", "CryptSignMessageWithKey", "CryptSIPAddProvider", "CryptSIPCreateIndirectData", "CryptSIPGetCaps", "CryptSIPGetSignedDataMsg", "CryptSIPLoad", "CryptSIPPutSignedDataMsg", "CryptSIPRemoveProvider", "CryptSIPRemoveSignedDataMsg", "CryptSIPRetrieveSubjectGuid", "CryptSIPRetrieveSubjectGuidForCatalogFile", "CryptSIPVerifyIndirectData", "CryptStringToBinary", "CryptUIDlgCertMgr", "CryptUIDlgSelectCertificate", "CryptUIDlgSelectCertificateFromStore", "CryptUIDlgViewCertificate", "CryptUIDlgViewContext", "CryptUIDlgViewSignerInfo", "CryptUIWizDigitalSign", "CryptUIWizExport", "CryptUIWizFreeDigitalSignContext", "CryptUIWizImport", "CryptUninstallDefaultContext", "CryptUnprotectData", "CryptUnprotectMemory", "CryptUpdateProtectedState", "CryptVerifyCertificateSignature", "CryptVerifyCertificateSignatureEx", "CryptVerifyDetachedMessageHash", "CryptVerifyDetachedMessageSignature", "CryptVerifyMessageHash", "CryptVerifyMessageSignature", "CryptVerifyMessageSignatureWithKey", "CryptVerifySignature", "CryptXmlAddObject", "CryptXmlClose", "CryptXmlCreateReference", "CryptXmlDigestReference", "CryptXmlDllCloseDigest", "CryptXmlDllCreateDigest", "CryptXmlDllCreateKey", "CryptXmlDllDigestData", "CryptXmlDllEncodeAlgorithm", "CryptXmlDllEncodeKeyValue", "CryptXmlDllFinalizeDigest", "CryptXmlDllGetAlgorithmInfo", "CryptXmlDllGetInterface", "CryptXmlDllSignData", "CryptXmlDllVerifySignature", "CryptXmlEncode", "CryptXmlGetAlgorithmInfo", "CryptXmlGetDocContext", "CryptXmlGetReference", "CryptXmlGetSignature", "CryptXmlGetStatus", "CryptXmlGetTransforms", "CryptXmlImportPublicKey", "CryptXmlOpenToDecode", "CryptXmlOpenToEncode", "CryptXmlSetHMACSecret", "CryptXmlSign", "CryptXmlVerifySignature", "FreeCryptProvFromCert", "FreeCryptProvFromCertEx", "Function", "GetCryptProvFromCert", "GetEncSChannel", "GetFriendlyNameOfCert", "pCryptSIPGetCaps", "PFNCFILTERPROC", "PvkFreeCryptProv", "PvkGetCryptProv", "PvkPrivateKeyAcquireContextFromMemory", "PvkPrivateKeySave", "RKeyCloseKeyService", "RKeyOpenKeyService", "RKeyPFXInstall", "SignerFreeSignerContext", "SignError", "SignerSign", "SignerSignEx", "SignerSignEx2", "SignerTimeStamp", "SignerTimeStampEx", "SignerTimeStampEx2", "SignerTimeStampEx3"]}
PEAPIs['Memory'] = { 'flag': 'M', 'calls' : ["AddSecureMemoryCacheCallback", "BadMemoryCallbackRoutine", "CopyMemory", "CreateMemoryResourceNotification", "DiscardVirtualMemory", "FillMemory", "GetLargePageMinimum", "GetMemoryErrorHandlingCapabilities", "GetPhysicallyInstalledSystemMemory", "GetSystemFileCacheSize", "GetWriteWatch", "GlobalMemoryStatusEx", "MoveMemory", "OfferVirtualMemory", "PrefetchVirtualMemory", "QueryMemoryResourceNotification", "ReclaimVirtualMemory", "RegisterBadMemoryNotification", "RemoveSecureMemoryCacheCallback", "ResetWriteWatch", "SecureMemoryCacheCallback", "SecureZeroMemory", "SetSystemFileCacheSize", "UnregisterBadMemoryNotification", "VirtualAlloc", "VirtualAllocEx", "VirtualAllocExNuma", "VirtualAllocFromApp", "VirtualFree", "VirtualFreeEx", "VirtualLock", "VirtualProtect", "VirtualProtectEx", "VirtualProtectFromApp", "VirtualQuery", "VirtualQueryEx", "VirtualUnlock", "ZeroMemory","AddDllDirectory", "DisableThreadLibraryCalls", "FreeLibrary", "FreeLibraryAndExitThread", "GetDllDirectory", "GetModuleFileName", "GetModuleFileNameEx", "GetModuleHandle", "GetModuleHandleEx", "GetProcAddress", "LoadLibrary", "LoadLibraryEx", "LoadPackagedLibrary", "RemoveDllDirectory", "SetDefaultDllDirectories", "SetDllDirectory"]}