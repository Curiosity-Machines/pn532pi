"""
    This example will attempt to connect to an ISO14443A
    card or tag and retrieve some basic information about it
    that can be used to determine what type of card it is.   
   
    To enable debug message, set DEBUG in nfc/PN532_log.h
"""
import time
import binascii

from pn532pi import Pn532, pn532
from pn532pi import Pn532I2c
from pn532pi import Pn532Spi
from pn532pi import Pn532Hsu

# Set the desired interface to True
SPI = True

if SPI:
    PN532_SPI = Pn532Spi(Pn532Spi.RPI_BUS1, Pn532Spi.SS2)
    nfc = Pn532(PN532_SPI)



def setup():
    nfc.begin()

    versiondata = nfc.getFirmwareVersion()
    print(hex(versiondata))
    if not versiondata:
        print("Didn't find PN53x board")
        raise RuntimeError("Didn't find PN53x board")  # halt

    # Got ok data, print it out!
    print("Found chip PN5 {:#x} Firmware ver. {:d}.{:d}".format((versiondata >> 24) & 0xFF, (versiondata >> 16) & 0xFF,
                                                                (versiondata >> 8) & 0xFF))
    # Set the max number of retry attempts to read from a card
    # This prevents us from waiting forever for a card, which is
    # the default behaviour of the pn532.
    nfc.setPassiveActivationRetries(0x00)

    # configure board to read RFID tags
    nfc.SAMConfig()

    print("Waiting for an ISO14443A card")

low_ma = ["illegal", "illegal", "25mA", "35mA"]
high_ma = ["45mA", "60mA", "75mA", "90mA", "105mA", "120mA", "130mA", "150mA"]

def presenceTest(low, high):
    if low == 2 or low == 3:
        if high < 8:
            test_mode = (low << 4) | (high << 1) | 0x01
            nfc.writeRegister(0x610c, test_mode)
            result = nfc.readRegister(0x610c)
            
            passed = "Test limits " + low_ma[low] + " to " + high_ma[high] + " : "

            if result & 0x80:
                passed += "FAIL CURRENT UNDER LOW THRESHOLD / "
            else:
                passed += "pass current above low threshold / "
            
            if result & 0x40:
                passed += "FAIL CURRENT OVER HIGH THRESHOLD "
            else:
                passed += "pass current under high threshold "
            
            if result & 0xC0:
                print(passed + "FAIL")
            else:
                print(passed + "ok")


def loop():
    
    if 0:
        nfc.writeRegister(0x6304, 0x00)
        print("tx: OFF " + hex(nfc.readRegister(0x6304)))
        time.sleep(5)
        
        for low in range(2,4):
            for high in range(0,8):
                presenceTest(low, high)
                time.sleep(0.1)

#        response = nfc.diagnose()
#        print(hex(response[0]))
        
        nfc.writeRegister(0x6304, 0x03)
        print("tx: ON " + hex(nfc.readRegister(0x6304)))
        time.sleep(5)
        
        for low in range(2,4):
            for high in range(0,8):
                presenceTest(low, high)
                time.sleep(0.1)
                
        success = False
    else:
        #success, uid = nfc.readPassiveTargetID(pn532.PN532_MIFARE_ISO14443A_106KBPS)
        success, uid = nfc.autoPoll(0xfe, 0x03)
        print(uid.hex())
        #success = False

    if (success):
        print("Found a card!")
        print("UID Length: {:d}".format(len(uid)))
        print("UID Value: {}".format(binascii.hexlify(uid)))
        
        if (len(uid) == 4):
            #  We probably have a Mifare Classic card ...
            print("Seems to be a Mifare Classic card (4 byte UID)")
            print("Trying to authenticate block 4 with default KEYA value")
            keya = bytearray([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
            success = nfc.mifareclassic_AuthenticateBlock(uid, 4, 0, keya)
    
            if (success):
                print("Sector 1 (Blocks 4..7) has been authenticated")
                success, data = nfc.mifareclassic_ReadDataBlock(4)
    
                if (success):
                    print("Reading Block 4: {}".format(binascii.hexlify(data)))
                    return True
    
                else:
                    print("Ooops ... unable to read the requested block.  Try another key?")
            else:
                print("Ooops ... authentication failed: Try another key?")
    
    
        elif len(uid) == 7:
            #  We probably have a Mifare Ultralight card ...
            print("Seems to be a Mifare Ultralight tag (7 byte UID)")
            #  Try to read the first general-purpose user page (#4)
            print("Reading page 4")
            success, data = nfc.mifareultralight_ReadPage(4)
            if (success):
                #  Data seems to have been read ... spit it out
                binascii.hexlify(data)
                return True
            else:
                print("Ooops ... unable to read the requested page!?")
                
        time.sleep(1)
        return True
    else:
        # pn532 probably timed out waiting for a card
        print("Timed out waiting for a card")
        return False

if __name__ == '__main__':
    setup()
    found = loop()
    while not found:
        found = loop()
