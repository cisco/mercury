// stun_params.h

#ifndef STUN_PARAMS_H
#define STUN_PARAMS_H

static const char unknown[] = "UNKNOWN";

enum method_type {
    Binding = 0x001,
    Allocate = 0x003,
    Refresh = 0x004,
    Send = 0x006,
    Data = 0x007,
    CreatePermission = 0x008,
    ChannelBind = 0x009,
    Connect = 0x00A,
    ConnectionBind = 0x00B,
    ConnectionAttempt = 0x00C,
    GOOG_PING = 0x080,
};

static const char *method_type_get_name(uint16_t t) {
    switch(t) {
    case Binding: return "Binding";
    case Allocate: return "Allocate";
    case Refresh: return "Refresh";
    case Send: return "Send";
    case Data: return "Data";
    case CreatePermission: return "CreatePermission";
    case ChannelBind: return "ChannelBind";
    case Connect: return "Connect";
    case ConnectionBind: return "ConnectionBind";
    case ConnectionAttempt: return "ConnectionAttempt";
    case GOOG_PING: return "GOOG_PING";
    default:
        ;
    }
    return unknown;
}

enum attribute_type {
    MAPPED_ADDRESS = 0x0001,
    USERNAME = 0x0006,
    MESSAGE_INTEGRITY = 0x0008,
    ERROR_CODE = 0x0009,
    UNKNOWN_ATTRIBUTES = 0x000A,
    CHANNEL_NUMBER = 0x000C,
    LIFETIME = 0x000D,
    XOR_PEER_ADDRESS = 0x0012,
    DATA = 0x0013,
    REALM = 0x0014,
    NONCE = 0x0015,
    XOR_RELAYED_ADDRESS = 0x0016,
    REQUESTED_ADDRESS_FAMILY = 0x0017,
    EVEN_PORT = 0x0018,
    REQUESTED_TRANSPORT = 0x0019,
    DONT_FRAGMENT = 0x001A,
    ACCESS_TOKEN = 0x001B,
    MESSAGE_INTEGRITY_SHA256 = 0x001C,
    PASSWORD_ALGORITHM = 0x001D,
    USERHASH = 0x001E,
    XOR_MAPPED_ADDRESS = 0x0020,
    RESERVATION_TOKEN = 0x0022,
    PRIORITY = 0x0024,
    USE_CANDIDATE = 0x0025,
    PADDING = 0x0026,
    RESPONSE_PORT = 0x0027,
    CONNECTION_ID = 0x002A,
    ADDITIONAL_ADDRESS_FAMILY = 0x8000,
    ADDRESS_ERROR_CODE = 0x8001,
    PASSWORD_ALGORITHMS = 0x8002,
    ALTERNATE_DOMAIN = 0x8003,
    ICMP = 0x8004,
    SOFTWARE = 0x8022,
    ALTERNATE_SERVER = 0x8023,
    TRANSACTION_TRANSMIT_COUNTER = 0x8025,
    CACHE_TIMEOUT = 0x8027,
    FINGERPRINT = 0x8028,
    ICE_CONTROLLED = 0x8029,
    ICE_CONTROLLING = 0x802A,
    RESPONSE_ORIGIN = 0x802B,
    OTHER_ADDRESS = 0x802C,
    ECN_CHECK_STUN = 0x802D,
    THIRD_PARTY_AUTHORIZATION = 0x802E,
    MOBILITY_TICKET = 0x8030,
    CISCO_STUN_FLOWDATA = 0xC000,
    ENF_FLOW_DESCRIPTION = 0xC001,
    ENF_NETWORK_STATUS = 0xC002,
    GOOG_NETWORK_INFO = 0xC057,
    GOOG_LAST_ICE_CHECK_RECEIVED = 0xC058,
    GOOG_MISC_INFO = 0xC059,
    GOOG_OBSOLETE_1 = 0xC05A,
    GOOG_CONNECTION_ID = 0xC05B,
    GOOG_DELTA = 0xC05C,
    GOOG_DELTA_ACK = 0xC05D,
    GOOG_MESSAGE_INTEGRITY_32 = 0xC060,
};

static const char *attribute_type_get_name(uint16_t t) {
    switch(t) {
    case MAPPED_ADDRESS: return "MAPPED_ADDRESS";
    case USERNAME: return "USERNAME";
    case MESSAGE_INTEGRITY: return "MESSAGE_INTEGRITY";
    case ERROR_CODE: return "ERROR_CODE";
    case UNKNOWN_ATTRIBUTES: return "UNKNOWN_ATTRIBUTES";
    case CHANNEL_NUMBER: return "CHANNEL_NUMBER";
    case LIFETIME: return "LIFETIME";
    case XOR_PEER_ADDRESS: return "XOR_PEER_ADDRESS";
    case DATA: return "DATA";
    case REALM: return "REALM";
    case NONCE: return "NONCE";
    case XOR_RELAYED_ADDRESS: return "XOR_RELAYED_ADDRESS";
    case REQUESTED_ADDRESS_FAMILY: return "REQUESTED_ADDRESS_FAMILY";
    case EVEN_PORT: return "EVEN_PORT";
    case REQUESTED_TRANSPORT: return "REQUESTED_TRANSPORT";
    case DONT_FRAGMENT: return "DONT_FRAGMENT";
    case ACCESS_TOKEN: return "ACCESS_TOKEN";
    case MESSAGE_INTEGRITY_SHA256: return "MESSAGE_INTEGRITY_SHA256";
    case PASSWORD_ALGORITHM: return "PASSWORD_ALGORITHM";
    case USERHASH: return "USERHASH";
    case XOR_MAPPED_ADDRESS: return "XOR_MAPPED_ADDRESS";
    case RESERVATION_TOKEN: return "RESERVATION_TOKEN";
    case PRIORITY: return "PRIORITY";
    case USE_CANDIDATE: return "USE_CANDIDATE";
    case PADDING: return "PADDING";
    case RESPONSE_PORT: return "RESPONSE_PORT";
    case CONNECTION_ID: return "CONNECTION_ID";
    case ADDITIONAL_ADDRESS_FAMILY: return "ADDITIONAL_ADDRESS_FAMILY";
    case ADDRESS_ERROR_CODE: return "ADDRESS_ERROR_CODE";
    case PASSWORD_ALGORITHMS: return "PASSWORD_ALGORITHMS";
    case ALTERNATE_DOMAIN: return "ALTERNATE_DOMAIN";
    case ICMP: return "ICMP";
    case SOFTWARE: return "SOFTWARE";
    case ALTERNATE_SERVER: return "ALTERNATE_SERVER";
    case TRANSACTION_TRANSMIT_COUNTER: return "TRANSACTION_TRANSMIT_COUNTER";
    case CACHE_TIMEOUT: return "CACHE_TIMEOUT";
    case FINGERPRINT: return "FINGERPRINT";
    case ICE_CONTROLLED: return "ICE_CONTROLLED";
    case ICE_CONTROLLING: return "ICE_CONTROLLING";
    case RESPONSE_ORIGIN: return "RESPONSE_ORIGIN";
    case OTHER_ADDRESS: return "OTHER_ADDRESS";
    case ECN_CHECK_STUN: return "ECN_CHECK_STUN";
    case THIRD_PARTY_AUTHORIZATION: return "THIRD_PARTY_AUTHORIZATION";
    case MOBILITY_TICKET: return "MOBILITY_TICKET";
    case CISCO_STUN_FLOWDATA: return "CISCO_STUN_FLOWDATA";
    case ENF_FLOW_DESCRIPTION: return "ENF_FLOW_DESCRIPTION";
    case ENF_NETWORK_STATUS: return "ENF_NETWORK_STATUS";
    case GOOG_NETWORK_INFO: return "GOOG_NETWORK_INFO";
    case GOOG_LAST_ICE_CHECK_RECEIVED: return "GOOG_LAST_ICE_CHECK_RECEIVED";
    case GOOG_MISC_INFO: return "GOOG_MISC_INFO";
    case GOOG_OBSOLETE_1: return "GOOG_OBSOLETE_1";
    case GOOG_CONNECTION_ID: return "GOOG_CONNECTION_ID";
    case GOOG_DELTA: return "GOOG_DELTA";
    case GOOG_DELTA_ACK: return "GOOG_DELTA_ACK";
    case GOOG_MESSAGE_INTEGRITY_32: return "GOOG_MESSAGE_INTEGRITY_32";
    default:
        ;
    }
    return unknown;
}

#endif // STUN_PARAMS_H
