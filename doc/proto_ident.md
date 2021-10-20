Protocol Identification Using Bitmasks

Mercury identifies protocol data elements with a lightweight method
that looks for bit patterns in the inital bytes of a data field.  This
process uses a bitmask and and expected value.  A good example of how
this works is that of the TLS Client Hello message.  The first six
bytes of that Protocol Data Unit (PDU) appear at the start of the TCP
Data field in each new TLS session.  The values of those bytes for
versions 1.0 through 1.3 of that protocol are

```
   16 03 01  *  * 01   v1.0 data
   16 03 02  *  * 01   v1.1 data
   16 03 03  *  * 01   v1.2 data
   16 03 03  *  * 01   v1.3 data
   ---------------------------------------
   ff ff fc 00 00 ff   mask
   16 03 00 00 00 01   value = data & mask
```

... where each byte is shown in hexadecimal.  The mask and value at
the bottom of the figure are byte strings that can be used to identify
when a data field holds that PDU, because the identity

```
   data & mask = value
```

always holds.

The program `string`, with the option `--find-mask`, can be used to find
a bitmask and corresponding value that matches a set of strings.