#ifndef FDC_H
#define FDC_H

#include "datum.h"
#include <stdint.h>

enum fieldtype : uint8_t {
    FINGERPRINT = 0,
    USER_AGENT  = 1,
    DOMAIN_NAME = 2,
    DST_IP_STR  = 3,
    DST_PORT    = 4
};

enum fdc_return {
    FDC_WRITE_INSUFFICIENT_SPACE = -1,
    FDC_WRITE_FAILURE = -2,
    MORE_PACKETS_NEEDED = -3,
    UNKNOWN_ERROR = -4
};

class FDC {
private:
    int bytes_written = 0;
    void copy_to_writeable(struct writeable* w, 
                        fieldtype type, 
                        const uint8_t *data, 
                        size_t length) {
        if(w->is_null() == false) w->copy((uint8_t)type);
        if(w->is_null() == false) w->copy(length);
        if(w->is_null() == false) w->copy(data, length);
    }
    void copy_to_writeable(struct writeable* w, 
                        uint16_t dst_port) {
        encoded<uint16_t> encoded_port{dst_port};
        if(w->is_null() == false) w->copy((uint8_t)fieldtype::DST_PORT);
        if(w->is_null() == false) w->copy(sizeof(uint16_t));
        if(w->is_null() == false) encoded_port.write(*w, true);
    }

public:
    FDC(const char* fp, 
        const char* ua, 
        const char* domain, 
        const char* dst_ip, 
        const uint16_t dst_port,
        writeable* w
    ) {
        uint8_t *start = w->data;

        std::vector<std::pair<fieldtype, const uint8_t*>> data_to_write = {
            {fieldtype::FINGERPRINT, (const uint8_t*)fp},
            {fieldtype::USER_AGENT, (const uint8_t*)ua},
            {fieldtype::DOMAIN_NAME, (const uint8_t*)domain},
            {fieldtype::DST_IP_STR, (const uint8_t*)dst_ip},
            {fieldtype::DST_PORT, (const uint8_t*)&dst_port}
        };

        for(auto& [field, data] : data_to_write) {
            if(field == fieldtype::DST_PORT) {
                copy_to_writeable(w, dst_port);
            } else {
                copy_to_writeable(w, field, data, strlen((const char*)data));
            }
            if(w->is_null()) break;
        }

        if(w->is_null()) {
            bytes_written = fdc_return::FDC_WRITE_INSUFFICIENT_SPACE;
        } else {
            bytes_written = w->data - start;
        }
    }

    int get_bytes_written_to_fdc() {
        return bytes_written;
    }
};

#endif /* FDC_H */