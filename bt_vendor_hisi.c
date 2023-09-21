/*
    File: bt_vendor_hisi.c
    Author: Arves100
    Date: 13 June 2022
    Reversed from: libbt-vendor-hisi.so (lib64)
*/

#include <android/log.h>
#include <hardware/bluetooth.h>
#include <bt_vendor_lib.h>

typedef struct HisiBtInfo
{
    int btFd;
    bt_vendor_callbacks_t* vcb;
    bt_bdaddr_t addr;
} HisiBtInfo;

typedef struct HisiCmdCallback
{
    ushort opcode;
} HisiCmdCallback;

static HisiBtInfo g_btInfo;

#define BTLOGNAME "bt_vendor_hisi"
#define BTLOGDBG(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, BTLOGNAME, fmt, ...)
#define BTLOGWARN(fmt, ...) __android_log_print(ANDROID_LOG_WARNING, BTLOGNAME, fmt, ...)

#define HISI_OPCODE_FWCFG 0xFC32
#define HISI_OPCODE_WRITE_BDADDR 0xFC0B

#define HISI_CMD_FULL_SIZE = sizeof(HisiCmdCallback) + sizeof(HC_BT_HDR);

static inline HC_BT_HDR* hc_bt_alloc(size_t len, ushort opcode)
{
    HC_BT_HDR* hdr = g_btInfo.vcb->malloc(HISI_CMD_FULL_SIZE + len);
    if (!hdr)
    {
        BTLOGWARN("HC_BT_HDR malloc fail!");
        return NULL;
    }

    hdr->len = len + sizeof(HisiCmdCallback);
    hdr->offset = 0;
    hdr->event = 0;
    hdr-> layer_specific = 0;
    return hdr;
}

static inline void hc_bt_reset(HC_BT_HDR* hdr, ushort event, ushort opcode)
{
    hdr->layer_specific = 0;
    hdr->offset = 0;
    hdr->event = evt;
    ((HisiCmdCallback*)&hdr->data)->opcode = opcode;
}

void int_cmd_cback(void* p_buf)
{
    HC_BT_HDR* hdr = p_buf;
    HisiCmdCallback* cmd = NULL;

    if (!g_btInfo.vcb || !p_buf)
        return;
    
    if (hdr->len < sizeof(HisiCmdCallback) || !hdr->data)
    {
        BTLOGWARN("Invalid HC_BT_HDR %d", hdr->len);
        return;
    }

    cmd = (HisiCmdCallback*)&hdr->data;

    if (cmd->opcode == HISI_OPCODE_FWCFG)
    {
        g_btInfo.vcb->fwcfg_cb(BT_VND_OP_RESULT_SUCCESS);
    }
    else if (cmd->opcode == HISI_OPCODE_WRITE_BDADDR)
    {
        if (g_btInfo.addr.address[0] | g_btInfo.addr.address[1] | g_btInfo.addr.address[2] | g_btInfo.addr.address[3] | g_btInfo.addr.address[4] | g_btInfo.addr.address[5])
        {
            hc_bt_reset(hdr, 0x92000, HISI_OPCODE_FWCFG);

            /* huawei original code wrote the g_btAddress in data, but it actually seems unused looking by the callbacks */

            g_btInfo.vcb->ximt_cb(HISI_OPCODE_FWCFG, hdr, int_cmd_cback);
            return; /* do not memory free as the buffer will be passed again to the cmd callback */
        }
    }
    else
    {
        BTLOGWARN("Unknown opcode %d", cmd->opcode);
    }

    g_btInfo.vcb->dealloc(data);
}

void hisi_cleanup(void)
{
    BTLOGDBG("vendor cleanup!!!");
    g_btInfo.vcb = NULL;

    if (g_btInfo.btFd != -1)
    {
        close(g_btInfo.btFd)
        g_btInfo.btFd = -1;
    }

    memset(g_btInfo.addr.address, 0, sizeof(g_btInfo.addr.address));
}

int hisi_init(bt_vendor_callbacks_t* vcb, const unsigned char* addr)
{
    __android_log_print(ANDROID_LOG_DEBUG, "bt_vendor_hisi", "vendor init!!!!!");

    if (vcb)
    {
        g_btInfo.bdFd = -1;
        g_btInfo.vcb = vcb;

        if (addr)
            memcpy(g_btInfo.addr.address, addr->address, sizeof(addr->address));
    }

    return 0;
}

int hisi_op(bt_vendor_opcode_t opcode, void* param)
{
    if (!g_btInfo.vcb)
        return 0;
    
    switch (opcode)
    {
        case BT_VND_OP_POWER_CTRL: /* power controller is ignored in hisi */
        case BT_VND_OP_SCO_CFG:
            break;
        case BT_VND_OP_USERIAL_CLOSE:
            if (g_btInfo.btFd != -1)
            {
                close(g_btInfo.btFd);
                g_btInfo.btFd = 0;
                BTLOGDBG("bluetooth uart close");
            }
            break;
        case BT_VND_OP_USERIAL_OPEN: /* get UART fds */
        {
            if (g_btInfo.btFd == -1)
            {
                BTLOGDBG("bluetooth uart open (/dev/hwbt)");
                g_btInfo.btFd = open(UAUI_BTUART_DEV);
                if (g_btInfo.btFd == -1)
                {
                    BTLOGWARN("bluetooth uart open fail! error: %s", strerror(errno_t));
                    return -1;
                }
            }

            /* one bluetooth channel is supplied from the kernel */
            *((int*)param) = g_btInfo.btFd;
            return 1;
        }

        case BT_VND_OP_LPM_SET_MODE:
            g_btInfo.vcb->lpm_cb(BT_VND_OP_RESULT_SUCCESS);
            break;

        case BT_VND_OP_EPILOG:
            g_btInfo.vcb->epilog_cb(BT_VND_OP_RESULT_SUCCESS);
            break;

        case BT_VND_OP_FW_CFG:
        {
            
            HC_BT_HDR* hdr;
#if 0
            int32_t puc;
            g_txpwr = get_cust_conf_int32(INIT_MODU_BT, "bt_txpwr_max", &puc) == INI_FAILED ? 5 : puc;
            if (get_cust_conf_int32(INIT_MODU_BT, "bt_feature_ble_hid", &puc) != INI_FAILED && puc)
                g_features |= BT_FEATURE_BLE_HID;
            if (get_cust_conf_int32(INIT_MODU_BT, "bt_feature_ble_priority", &puc) != INI_FAILED && puc)
                g_features |= BT_FEATURE_BLE_PRIORITY;
            if (get_cust_conf_int32(INIT_MODU_BT, "bt_feature_log", &puc) != INI_FAILED)
                g_log = puc;
            if (get_cust_conf_int32(INIT_MODU_BT, "bt_feature_32k_clock", &puc) != INI_FAILED)
                g_32kClock = puc;

            /* huawei original code sends [6 bytes if there's no get_hisi_connect and 8 if there is]
                sending off:
                    no hisi connectivity:
                        [4] [0] [51] [bt features] [log features] [32bit clock]
                    hisi connectivity:
                        [128] [0] then the same data as no hisi connectivity
                
                I have no idea why it was done this way considering the command 0xFC0B does not expect any parameter
            */
#endif

            hdr = hc_bt_alloc(0, HISI_OPCODE_FWCFG);

            if (!hdr)
            {
                return -1; /* error? */
            }

            g_btInfo.vcb->ximt_cb(HISI_OPCODE_FWCFG, hdr, int_cmd_cback);
            break;
        }

        case BT_VND_OP_SET_AUDIO_STATE:
            break;

        default:
            BTLOGDBG("Invalid opcode %u", opcode);
            return 1;
    }

    return 0;
}


/* android ep */
const bt_vendor_interface_t BLUETOOTH_VENDOR_LIB_INTERFACE = {
    sizeof(bt_vendor_interface_t),
    hisi_init,
    hisi_op,
    hisi_cleanup
};
