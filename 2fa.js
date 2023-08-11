class TwoFA {
    static async gen(secret) {
        secret = TwoFA.decode( secret );

        let time = 30;
        let _t = Date.now();

        let counter = Math.floor((_t / 1000) / time);

        let b = TwoFA.intToBytes(counter);

        let digest = await TwoFA.hmacSHA1(secret, b);

        let h = TwoFA.hexToBytes(digest);

        let offset = h[19] & 0xf;
        let v = (h[offset] & 0x7f) << 24 |
            (h[offset + 1] & 0xff) << 16 |
            (h[offset + 2] & 0xff) << 8  |
            (h[offset + 3] & 0xff);

        v = (v % 1000000) + '';

        return new Array(7-v.length).join('0') + v;
    }

    static hexToBytes(hex) {
        let bytes = [];
    
        for(let c = 0, C = hex.length; c < C; c += 2) {
            bytes.push(parseInt(hex.substr(c, 2), 16));
        }
        return new Uint8Array(bytes);
    }

    static intToBytes(num) {
        let bytes = [];

        for(var i=7 ; i>=0 ; --i) {
            bytes[i] = num & (255);
            num = num >> 8;
        }

        return new Uint8Array(bytes);
    }

    static decode(encoded) {

        const byteTable = [
            0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff
        ];

        if (typeof encoded !== "string") return null;

        let shiftIndex = 0;
        let plainDigit = 0;
        let plainChar;
        let plainPos = 0;

        encoded = [...encoded].map(e => e.charCodeAt());

        let decoded = new Uint8Array(Math.ceil(encoded.length * 5 / 8));

        for (var i = 0; i < encoded.length; i++) {
            if (encoded[i] === 0x3d) {
                break;
            }
            let encodedByte = encoded[i] - 0x30;
            if (encodedByte < byteTable.length) {
                plainDigit = byteTable[encodedByte];
                if (shiftIndex <= 3) {
                    shiftIndex = (shiftIndex + 5) % 8;
                    if (shiftIndex === 0) {
                        plainChar |= plainDigit;
                        decoded[plainPos] = plainChar;
                        plainPos++;
                        plainChar = 0;
                    }
                    else {
                        plainChar |= 0xff & (plainDigit << (8 - shiftIndex));
                    }
                }
                else {
                    shiftIndex = (shiftIndex + 5) % 8;
                    plainChar |= 0xff & (plainDigit >>> shiftIndex);
                    decoded[plainPos] = plainChar;
                    plainPos++;
                    plainChar = 0xff & (plainDigit << (8 - shiftIndex));
                }
            }
            else {
                return null;
            }
        }
        return new Uint8Array( decoded.slice(0, plainPos) );
    };

    static async hmacSHA1(keyData, messageData) {
        const importedKey = await crypto.subtle.importKey(
            "raw",
            keyData,
            { name: "HMAC", hash: "SHA-1" },
            false,
            ["sign"]
        );

        const signatureBuffer = await crypto.subtle.sign("HMAC", importedKey, messageData);
        const signatureArray = new Uint8Array(signatureBuffer);

        let hmacSHA1Result = "";
        signatureArray.forEach(byte => {
            hmacSHA1Result += byte.toString(16).padStart(2, "0");
        });

        return hmacSHA1Result;
    }
}