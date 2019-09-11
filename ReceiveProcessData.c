#include <stdlib.h> 
#include <stddef.h>
#include <string.h>
#include <time.h> 
#include <sys/byteorder.h>
#include <sys/printk.h>

//#include "peer_manager.h"  
#include "data_protocol.h"
//#include "nrf_crypto.h"
//#include "nrf_crypto_error.h"

#define  MAX_DATA_PROTOCOL_MESSAGE_SIZE    200
#define  LITTLE_ENDIAN                     true //We assuming that this software is running on ARM processor 
//#define  SCM_DEVICE                        true
#define  BSM_DEVICE                        true
#define  DATA_BUS_WIDENESS                 32
//#define AES_ENCODING                      true
//#define PEER_MANAGEMENT_ENABLE              true   
//----------------------------------------------------------------------------------------------------------
void encrypt_cbc(void);
void decrypt_cbc(void);
void convert_big_endian_to_little_endian_and_back(unsigned char *src, unsigned char *dest, short int length);
void process_message(void);
long int calculateCRC32(void);
long int calculateCRC32resp(void);
void SetTimeInside(MessageTimestamp *timestamp);
MessageTimestamp *GetInsideTimeinTimestamp(void);
uint8_t GetTimeInsideAwake(void);
void OutReportStatus(void);
void OutRunDiagnostics(void);
void OutSetTime(void);
void OutConfirmARM(void);
void OutEventLogMessage(void);
void OutRejectARM(void);
void OutPairing(int status);
void OutUnPairing(void);
void OutDISARM(void);
void OutEraseEventLog(void);
void OutConfigureSensor(void);
void OutEventLog(void);
void SolicitedMessage(void);
void AcknoweledgementMessage(int status);
void OutEventLogMessage(void);
//----------------------------------------------------------------------------------------------------------

//------------incoming and outcoming messages spaces--------------------------------------------------------
static unsigned char incoming_message[MAX_DATA_PROTOCOL_MESSAGE_SIZE];
static int incoming_message_length;
static unsigned char outcoming_message[MAX_DATA_PROTOCOL_MESSAGE_SIZE];
static int outcoming_message_length;
static unsigned char local_message_in[MAX_DATA_PROTOCOL_MESSAGE_SIZE];
static int local_message_in_length;
static unsigned char local_message_out[MAX_DATA_PROTOCOL_MESSAGE_SIZE];
static int local_message_out_length;
static unsigned char local_message_in_decr[MAX_DATA_PROTOCOL_MESSAGE_SIZE];
static int local_message_in_decr_length;
static unsigned char local_message_out_decr[MAX_DATA_PROTOCOL_MESSAGE_SIZE];
static int local_message_out_decr_length;

//----------------------------------------------------------------------------------------------------------
int ready_to_process_flag = 0;
int ready_to_send_flag = 0;
static int armed = 0;
static int paired = 0;
static int time_set = 0;
static long int ascension_number = 0;
static MessageTimestamp startTime;
#ifdef AES_ENCODING
/* Maximum allowed key = 256 bit */
static uint8_t m_key[32] = {'N', 'O', 'R', 'D', 'I', 'C', ' ',
                            'S', 'E', 'M', 'I', 'C', 'O', 'N', 'D', 'U', 'C', 'T', 'O', 'R',
                            'A', 'E', 'S', ' ', 'C', 'B', 'C', ' ', 'T', 'E', 'S', 'T'};
#endif
void data_to_send(u8_t *data,u16_t *len)
{
   memcpy(data, &outcoming_message[0],outcoming_message_length);
   *len = outcoming_message_length;
}
void data_handler_rx(u8_t *data,u16_t len)
{

        printk("BSM received message %d bytes", len);
        ready_to_process_flag = 1;
        ready_to_send_flag = 0;

	if(len > MAX_DATA_PROTOCOL_MESSAGE_SIZE)
        {
           printk("Incoming message too long");
 	}			
	memcpy(&incoming_message[0],data,len);
	incoming_message_length = len;
#ifdef SCM_DEVICE
        //In case of SCM we just transfer data to BSM
        outcoming_message_length = incoming_message_length; 
        memcpy(&outcoming_message[0],&incoming_message[0],outcoming_message_length);
#else
#ifdef BSM_DEVICE
        process_message();
	encrypt_cbc();
#endif

#ifdef LITTLE_ENDIAN
        convert_big_endian_to_little_endian_and_back(&local_message_out[0],&outcoming_message[0],local_message_out_length);
#else
	    memcpy(&outcoming_message[0],&local_message_out[0],local_message_out_length);
#endif
        
	outcoming_message_length = local_message_out_length;
#endif  
	printk("Transmitting response of command to central.\n");
        ready_to_process_flag = 0;
        ready_to_send_flag = 1;
}
void process_message(void)
{
	   long int calculated_crc = 0;
	   MSGPayload *payload = (MSGPayload *)&local_message_in_decr[sizeof(SMessageHeader)];
	   MsgIntegrity *checksum_in = (MsgIntegrity *)&local_message_in_decr[sizeof(SMessageHeader)];
#ifdef PEER_MANAGEMENT_ENABLE
	   SMessageHeader *hdr = (SMessageHeader *)&local_message_out_decr[0];
	   pm_peer_id_t *p_peers;
	   ble_gap_addr_t * p_addrs;
	   uint32_t p_size;
	   int count;
#endif
	   
#ifdef LITTLE_ENDIAN
        convert_big_endian_to_little_endian_and_back(&incoming_message[0],&local_message_in[0],incoming_message_length);
#else
        memcpy(&local_message[0],&incoming_message[0],incoming_message_length);
#endif
        local_message_in_length = incoming_message_length;
		decrypt_cbc();
		//Processing successfully received message
		switch(payload->data[0])//Always correspond to OP_Code
		{
			case ReportStatus: 
			     checksum_in += sizeof(ReportStatusPayload);
			     ascension_number++;
			     OutReportStatus();
				break;
			case RunDiagnostics:
			     checksum_in += sizeof(RunDiagnosticsPayload);
			     OutRunDiagnostics();
			    break;
	        case SetTime:
			     time_set = 1;
				 checksum_in += sizeof(SetTimePayload);
				 SetTimeInside((MessageTimestamp *)&payload + sizeof(MessageTimestamp));
			     OutSetTime();
				break;
	        case ARM:
			     checksum_in += sizeof(ARMPayload);
			     if(armed == 1)
				 {
					 OutRejectARM();
				 }
				 else
				 {
					 armed = 1;
					 OutConfirmARM();
				 }
			    break;
	        case PairCommand:
			     checksum_in += sizeof(PairCommandPayload);
#ifdef PEER_MANAGEMENT_ENABLE
			     if( pm_peer_count() >= BLE_GAP_WHITELIST_ADDR_MAX_COUNT) {
				   OutPairing(1);
				 }
                            else {			   
					if(pm_id_addr_set((ble_gap_addr_t const *)&hdr->sa.sa_data[0]) == NRF_SUCCESS)
					{
#endif
						paired = 1;
						OutPairing(0);
#ifdef PEER_MANAGEMENT_ENABLE
					}
					else
					{
						OutPairing(1);
					}
				 }
#endif
			    break;
	        case UnPairCommand:
			     checksum_in += sizeof(UnPairCommandPayload);
#ifdef PEER_MANAGEMENT_ENABLE
			     p_size = pm_peer_count();
			     p_peers = calloc(sizeof(pm_peer_id_t),BLE_GAP_WHITELIST_ADDR_MAX_COUNT);
			     pm_peer_id_list(p_peers, &p_size,(pm_peer_id_t)1,(pm_peer_id_t)0);
			     for(count = 0; count < BLE_GAP_WHITELIST_ADDR_MAX_COUNT; count++)
			     {   //Removing peer corresponding MAC address
			         p_addrs = NULL;
			         if(pm_id_addr_get(p_addrs) == NRF_SUCCESS)
				 {
				    pm_whitelist_get(p_addrs,
                                            &p_size,
                                            NULL,
		                            NULL);
		         	    if(memcmp(p_addrs,&(hdr->sa.sa_data[0]),sizeof(SourceAddress)) == 0)
		    		    {
					pm_peer_delete(*p_peers);
					break;
		         	    }
				 }
		        	 p_peers++;
			     }
#endif
			     paired = 0;
			     OutUnPairing();
			    break;
	        case DISARM:
			     checksum_in += sizeof(DISARMPayload);
			     armed = 0;
				 OutDISARM();
			    break;
	        case SendAllEventLog:
			     checksum_in += sizeof(SendAllEventLogPayload);
			     ascension_number++;
			     OutEventLog();
			    break;
	        case EraseEventLog:
			     checksum_in += sizeof(EraseEventLogPayload);
			     OutEraseEventLog();
			    break;
	        case ConfigureSensor:
			     checksum_in += sizeof(ConfigureSensorPayload);
			     OutConfigureSensor();
			    break;
			default:
                          printk("Bad or unimplemented operation\n");
			  break;
		}
		calculated_crc = calculateCRC32();
		if(calculated_crc != checksum_in->m_d)
		{
	           //We just ignore it because BLE has own CRC check
		   printk("CRC sum is BAD\n");
		}
}
void OutReportStatus(void)
{
	SolicitedMessage();
}
void OutRunDiagnostics(void)
{
	SolicitedMessage();
}
void OutSetTime(void)
{
	AcknoweledgementMessage(0);
}
void OutConfirmARM(void)
{
	AcknoweledgementMessage(0);
}
void OutRejectARM(void)
{
	AcknoweledgementMessage(1);
}
void OutPairing(int status)
{
	AcknoweledgementMessage(status);
}
void OutUnPairing(void)
{
	AcknoweledgementMessage(0);
}
void OutDISARM(void)
{
	AcknoweledgementMessage(0);
}
void OutEraseEventLog(void)
{
	AcknoweledgementMessage(0);
}
void OutConfigureSensor(void)
{
	AcknoweledgementMessage(0);
}
void OutEventLog(void)
{
	OutEventLogMessage();
}
void SolicitedMessage(void)
{
  MsgSolicitedPaylodResponse *response_ptr = (MsgSolicitedPaylodResponse *)&local_message_out_decr[sizeof(SMessageHeader)];
  SMessageHeader *response_hdr_ptr = (SMessageHeader *)&local_message_out_decr[0];
  SMessageHeader *request_hdr_ptr = (SMessageHeader *)&local_message_in_decr[0];
  MsgIntegrity_d *crc_ptr = (MsgIntegrity_d *)&local_message_out_decr[sizeof(SMessageHeader) + sizeof(Status_Summary)];
  uint32_t checksum;
  
  
     response_ptr->ss.ssb.Diag_Status = 1;
  
     response_ptr->ss.ssb.Pwr_Status = 1;
  
  if(paired == 1)
    response_ptr->ss.ssb.Pairing_Status = 0;
  else
    response_ptr->ss.ssb.Pairing_Status = 1;

  if(armed == 1)
	response_ptr->ss.ssb.Arming_Status = 0;
  else
	response_ptr->ss.ssb.Arming_Status = 1; 

  if(time_set == 1)
	response_ptr->ss.ssb.Time_Set_Status = 0;
  else
	response_ptr->ss.ssb.Time_Set_Status = 1;  

  //response_ptr->ss.as; TBD

  response_ptr->ss.at.at_d = GetTimeInsideAwake();
  
  //response_ptr->ss.rc TBD
  
  response_ptr->ss.aa.aa_d = (uint16_t)ascension_number;
  
  response_hdr_ptr->st = BSM;
  response_hdr_ptr->mt = SolictedStatusMessage;
  response_hdr_ptr->ml = sizeof(Status_Summary) + sizeof(MsgIntegrity);
  memcpy(&response_hdr_ptr->sa.sa_data[0],&request_hdr_ptr->da.da_data[0],sizeof(SourceAddress));
  memcpy(&response_hdr_ptr->da.da_data[0],&request_hdr_ptr->sa.sa_data[0],sizeof(SourceAddress));
  response_hdr_ptr->icd_rev = request_hdr_ptr->icd_rev;
  response_hdr_ptr->msga = request_hdr_ptr->msga;
  response_hdr_ptr->rp = request_hdr_ptr->rp;
  
  checksum = calculateCRC32resp();
  memcpy(crc_ptr,&checksum,sizeof(MsgIntegrity));
  local_message_out_decr_length = sizeof(SMessageHeader) + sizeof(Status_Summary) + sizeof(MsgIntegrity);
}
void AcknoweledgementMessage(int status)
{
  ACK *response_ptr = (ACK *)&local_message_out_decr[sizeof(SMessageHeader)];
  SMessageHeader *response_hdr_ptr = (SMessageHeader *)&local_message_out_decr[0];
  SMessageHeader *request_hdr_ptr = (SMessageHeader *)&local_message_in_decr[0];
  MsgIntegrity_d *crc_ptr = (MsgIntegrity_d *)&local_message_out_decr[sizeof(SMessageHeader) + sizeof(ACK)];
  uint32_t checksum;
  
  response_ptr->a_d.aa = (uint16_t)ascension_number;
  response_ptr->a_d.aw = status;
  
  response_hdr_ptr->st = BSM;
  response_hdr_ptr->mt = ACKMessage;
  response_hdr_ptr->ml = sizeof(ACK) + sizeof(MsgIntegrity);
  memcpy(&response_hdr_ptr->sa.sa_data[0],&request_hdr_ptr->da.da_data[0],sizeof(SourceAddress));
  memcpy(&response_hdr_ptr->da.da_data[0],&request_hdr_ptr->sa.sa_data[0],sizeof(SourceAddress));
  response_hdr_ptr->icd_rev = request_hdr_ptr->icd_rev;
  response_hdr_ptr->msga = request_hdr_ptr->msga;
  response_hdr_ptr->rp = request_hdr_ptr->rp;
  
  checksum = calculateCRC32resp();
  memcpy(crc_ptr,&checksum,sizeof(MsgIntegrity));
  local_message_out_decr_length = sizeof(SMessageHeader) + sizeof(ACK) + sizeof(MsgIntegrity);
}
void OutEventLogMessage(void)
{
  MsgPayloadEventLogResponse *response_ptr = (MsgPayloadEventLogResponse *)&local_message_out_decr[sizeof(SMessageHeader)];
  SMessageHeader *response_hdr_ptr = (SMessageHeader *)&local_message_out_decr[0];
  SMessageHeader *request_hdr_ptr = (SMessageHeader *)&local_message_in_decr[0];
  MsgIntegrity_d *crc_ptr = (MsgIntegrity_d *)&local_message_out_decr[sizeof(SMessageHeader) + sizeof(MsgPayloadEventLogResponse)];
  uint32_t checksum;
  
  response_ptr->aelr = (uint16_t)ascension_number;
  //response_ptr->etp  TBD
  memcpy(&response_ptr->et.et_d,GetInsideTimeinTimestamp(),sizeof(MessageTimestamp));
  response_ptr->lrr = (uint8_t)100;
  
  response_hdr_ptr->st = BSM;
  response_hdr_ptr->mt = DeviceEventLogRecord;
  response_hdr_ptr->ml = sizeof(MsgPayloadEventLogResponse) + sizeof(MsgIntegrity);
  memcpy(&response_hdr_ptr->sa.sa_data[0],&request_hdr_ptr->da.da_data[0],sizeof(SourceAddress));
  memcpy(&response_hdr_ptr->da.da_data[0],&request_hdr_ptr->sa.sa_data[0],sizeof(SourceAddress));
  response_hdr_ptr->icd_rev = request_hdr_ptr->icd_rev;
  response_hdr_ptr->msga = request_hdr_ptr->msga;
  response_hdr_ptr->rp = request_hdr_ptr->rp;
  
  checksum = calculateCRC32resp();
  memcpy(crc_ptr,&checksum,sizeof(MsgIntegrity));
  local_message_out_decr_length = sizeof(SMessageHeader) + sizeof(MsgPayloadEventLogResponse) + sizeof(MsgIntegrity);

}
//Service routines------------------------------------------------------------------------------------------------------
void SetTimeInside(MessageTimestamp *timestamp)
{
    time_t time;
    u16_t year;

	/* 'Exact Time 256' contains 'Day Date Time' which contains
	 * 'Date Time' - characteristic contains fields for:
	 * year, month, day, hours, minutes and seconds.
	 */

	year = sys_cpu_to_le16(timestamp->m_d.year + 30);//Linux start epox 1970, AKUA start epox 2000
        time = year;
        time *= 3600*30*24*12;
	time += 3600*30*24*timestamp->m_d.month; /* months starting from 1 */
	time += 3600*24*timestamp->m_d.day; /* day */
        time += 3600*timestamp->m_d.hour; /* hours */
	time += 60*timestamp->m_d.minute; /* minutes */
	time += timestamp->m_d.seconds; /* seconds */
        gmtime(time);
}
uint8_t GetTimeInsideAwake(void)
{
	struct tm  ts_start,ts_now;
	uint8_t time_diff;
	memcpy(&ts_now,gmtime(0), sizeof(struct tm));
	
        time_diff= sys_get_le32(startTime.m_d.year) - sys_get_le32(ts_now.tm_year);
        time_diff += startTime.m_d.month - ts_now.tm_mon;
        time_diff += startTime.m_d.day - ts_now.tm_mday;
	
	return time_diff;
}

MessageTimestamp *GetInsideTimeinTimestamp(void)
{
	struct tm ts;
	static MessageTimestamp currTime;	
	
	memcpy(&ts,gmtime(0),sizeof(struct tm));
	
	currTime.m_d.seconds = ts.tm_sec;
    currTime.m_d.minute = ts.tm_min;
    currTime.m_d.hour = ts.tm_hour;
    currTime.m_d.day = ts.tm_mday;
    currTime.m_d.month = ts.tm_mon;
	currTime.m_d.year = ts.tm_year - 30 ; //Linux start epox 1970, AKUA 2000
	
	return &currTime; 
}

void convert_big_endian_to_little_endian_and_back(unsigned char *src, unsigned char *dest, short int length)
{
	short int chunks, index, piece;
	
	chunks = (int)(length/DATA_BUS_WIDENESS - 0.5);
	chunks++;
	for(piece = 0; piece < chunks; piece++) {
	    for(index = 0; index < DATA_BUS_WIDENESS; index++) {
	        *dest++ = *(src + DATA_BUS_WIDENESS - 1 - index)  ;
		}
	    dest += DATA_BUS_WIDENESS;
		src  += DATA_BUS_WIDENESS;
	}
}

void encrypt_cbc(void)
{
#ifdef AES_ENCODING	
	uint8_t     iv[16];
    ret_code_t  ret_val;

	static nrf_crypto_aes_context_t cbc_encr_128_ctx; // AES CBC encryption context
	
	NRF_LOG_RAW_INFO("Decripted outgoing message.");
    NRF_LOG_HEXDUMP_DEBUG(&local_message_out_decr[0],local_message_out_decr_length);
	
	/* Init encryption context for 128 bit key and PKCS7 padding mode */
    ret_val = nrf_crypto_aes_init(&cbc_encr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_pad_pkcs7_info,
                                  NRF_CRYPTO_ENCRYPT);
    APP_ERROR_CHECK(ret_val);

    /* Set key for encryption context - only first 128 key bits will be used */
    ret_val = nrf_crypto_aes_key_set(&cbc_encr_128_ctx, m_key);
    APP_ERROR_CHECK(ret_val);

    memset(iv, 0, sizeof(iv));
    /* Set IV for encryption context */

    ret_val = nrf_crypto_aes_iv_set(&cbc_encr_128_ctx, iv);
    APP_ERROR_CHECK(ret_val);

    // Header of the message decripted all the time
    memcpy(&local_message_out[0],&local_message_out_decr[0],sizeof(SMessageHeader));


    ret_val = nrf_crypto_aes_finalize(&cbc_encr_128_ctx,
                                      (uint8_t *)&local_message_out_decr[sizeof(SMessageHeader)],
                                      local_message_out_decr_length - sizeof(SMessageHeader),
                                      (uint8_t *)&local_message_out[sizeof(SMessageHeader)],
                                      (unsigned int *)&local_message_out_length);
    APP_ERROR_CHECK(ret_val);
	
	local_message_out_length += sizeof(SMessageHeader);
	
	NRF_LOG_RAW_INFO("Encripted outgoing message.");
    NRF_LOG_HEXDUMP_DEBUG(&local_message_out[0],local_message_out_length);
#else
	memcpy(&local_message_out[0],&local_message_out_decr[0],local_message_out_decr_length);
    local_message_out_length = local_message_out_decr_length;
#endif
}

void decrypt_cbc(void)
{
#ifdef AES_ENCODING
	uint8_t     iv[16];
    ret_code_t  ret_val;

    static nrf_crypto_aes_context_t cbc_decr_128_ctx; // AES CBC decryption context

    NRF_LOG_RAW_INFO("Encripted incoming message.");
    NRF_LOG_HEXDUMP_DEBUG(&local_message_in[0],local_message_in_length);
	
	/* Init decryption context for 128 bit key and PKCS7 padding mode */
    ret_val = nrf_crypto_aes_init(&cbc_decr_128_ctx,
                                  &g_nrf_crypto_aes_cbc_128_pad_pkcs7_info,
                                  NRF_CRYPTO_DECRYPT);
    APP_ERROR_CHECK(ret_val);


    /* Set key for decryption context - only first 128 key bits will be used */
    ret_val = nrf_crypto_aes_key_set(&cbc_decr_128_ctx, m_key);
    APP_ERROR_CHECK(ret_val);

    memset(iv, 0, sizeof(iv));
    /* Set IV for decryption context */

    ret_val = nrf_crypto_aes_iv_set(&cbc_decr_128_ctx, iv);
    APP_ERROR_CHECK(ret_val);
	
    // Header of the message decripted all the time
    memcpy(&local_message_in_decr[0],&local_message_in[0],sizeof(SMessageHeader));

    /* Decrypt text */
    ret_val = nrf_crypto_aes_finalize(&cbc_decr_128_ctx,
                                      (uint8_t *)&local_message_in[sizeof(SMessageHeader)],
                                      local_message_in_length - sizeof(SMessageHeader),
                                      (uint8_t *)&local_message_in_decr[sizeof(SMessageHeader)],
                                      (unsigned int *)&local_message_in_decr_length);
    APP_ERROR_CHECK(ret_val);

    /* trim padding */
    local_message_in_decr[local_message_in_decr_length + sizeof(SMessageHeader)] = '\0';
	
	local_message_in_decr_length += sizeof(SMessageHeader);
	
    NRF_LOG_RAW_INFO("Decripted incoming message.\n");
    NRF_LOG_HEXDUMP_DEBUG(&local_message_in_decr[0],local_message_in_decr_length);
#else
	memcpy(&local_message_in_decr[0],&local_message_in[0],local_message_in_length);
    local_message_in_decr_length = local_message_in_length;
#endif
}

long int calculateCRC32(void)
{
    	const uint8_t *p = &local_message_in_decr[0];
		SMessageHeader *ps = (SMessageHeader *)&local_message_in_decr[0]; 
		uint32_t size = (uint32_t)sizeof(SMessageHeader) + (uint32_t)ps->ml - (uint32_t)sizeof(MsgIntegrity); 
 		uint32_t crc;
 
 		crc = ~0U;
 		while (size--)
 			crc = ((crc ^ *p++) & 0xFF) ^ (crc >> 8);
 		return (long int)(crc ^ ~0U);
}

long int calculateCRC32resp(void)
{
    	const uint8_t *p = &local_message_out_decr[0];
		SMessageHeader *ps = (SMessageHeader *)&local_message_in_decr[0];
		uint32_t size = (uint32_t)sizeof(SMessageHeader) + (uint32_t)ps->ml - (uint32_t)sizeof(MsgIntegrity); 
 		uint32_t crc;
 
 		crc = ~0U;
 		while (size--)
 			crc = ((crc ^ *p++) & 0xFF) ^ (crc >> 8);
 		return (long int)(crc ^ ~0U);
}
