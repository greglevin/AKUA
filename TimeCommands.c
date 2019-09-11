#include <time.h>
#include <stdio.h>

#include "data_protocol.h"


#define  MAX_DATA_PROTOCOL_MESSAGE_SIZE    200
#define  LITTLE_ENDIAN                     true //We assuming that this software is running on ARM processor 
#define  DATA_BUS_WIDENESS                 32

static unsigned char incoming_message[MAX_DATA_PROTOCOL_MESSAGE_SIZE];
static int incoming_message_length;
static unsigned char outcoming_message[MAX_DATA_PROTOCOL_MESSAGE_SIZE];
static int outcoming_message_length;
MessageTimestamp *GetInsideTimeinTimestamp(void);
void convert_big_endian_to_little_endian_and_back(unsigned char *src, unsigned char *dest, short int length);
long int calculateCRC32(unsigned char *data);

void FormSetTimeCommand(u8_t *data, u16_t *len)
{
	SMessageHeader *request_hdr_ptr = (SMessageHeader *)&incoming_message[0];
	MsgIntegrity_d *crc_ptr = (MsgIntegrity_d *)(&incoming_message[0] + sizeof(OP_code_command) + sizeof(SMessageHeader) + sizeof(MessageTimestamp) + sizeof(SynchTime));
        MessageTimestamp *tstamp = (MessageTimestamp *)(&incoming_message[0] + sizeof(SMessageHeader) + sizeof(OP_code_command));
	SynchTime *stime =(SynchTime *)(&incoming_message[0] + sizeof(SMessageHeader) + sizeof(MessageTimestamp) + sizeof(OP_code_command));
        OP_code_command *op =(OP_code_command *)(&incoming_message[0] + sizeof(SMessageHeader)); 
    //Forming message header
    request_hdr_ptr->st = SensorController;
    request_hdr_ptr->mt = SetTime;
    request_hdr_ptr->ml = sizeof(MessageTimestamp) + sizeof(SynchTime) + sizeof(MsgIntegrity);
    memcpy(&request_hdr_ptr->sa.sa_data[0],"EC6F49972861",sizeof(SourceAddress));
    memcpy(&request_hdr_ptr->da.da_data[0],"EC6F49972861",sizeof(SourceAddress));
    request_hdr_ptr->icd_rev = 6;
    memcpy(&request_hdr_ptr->msga,"1111",sizeof(MSGAscension));
    request_hdr_ptr->rp = 1;
    *op = SetTime;
    //Forming timestamp
	memcpy((void *)tstamp,(void *)GetInsideTimeinTimestamp(),sizeof(MessageTimestamp));
	//Forming SynchTime
	memcpy((void *)stime,(void *)GetInsideTimeinTimestamp(),sizeof(SynchTime));
	//Forming CRC
	*crc_ptr = calculateCRC32(data);
	outcoming_message_length = sizeof(SMessageHeader) + sizeof(MessageTimestamp) + sizeof(SynchTime) + sizeof(MsgIntegrity);
#ifdef LITTLE_ENDIAN
    convert_big_endian_to_little_endian_and_back(&incoming_message[0],&outcoming_message[0], outcoming_message_length);
	memcpy(data,&outcoming_message[0],outcoming_message_length);
#else
	memcpy(data,&incoming_message[0],outcoming_message_length);
#endif
    *len = sizeof(SMessageHeader) + sizeof(MessageTimestamp) + sizeof(SynchTime) + sizeof(MsgIntegrity);
}

void FormReportStatusCommand(u8_t *data, u16_t *len)
{
	SMessageHeader *request_hdr_ptr = (SMessageHeader *)&incoming_message[0];
	MsgIntegrity_d *crc_ptr = (MsgIntegrity_d *)(&incoming_message[0] + sizeof(SMessageHeader) + sizeof(OP_code_command) + sizeof(MessageTimestamp));
    MessageTimestamp *tstamp = (MessageTimestamp *)(&incoming_message[0] + sizeof(SMessageHeader) + sizeof(OP_code_command));
        OP_code_command *op =(OP_code_command *)(&incoming_message[0] + sizeof(SMessageHeader));
    //Forming message header
    request_hdr_ptr->st = SensorController;
    request_hdr_ptr->mt = ReportStatus;
    request_hdr_ptr->ml = sizeof(MessageTimestamp) + sizeof(MsgIntegrity);
    memcpy(&request_hdr_ptr->sa.sa_data[0],"EC6F49972861",sizeof(SourceAddress));
    memcpy(&request_hdr_ptr->da.da_data[0],"EC6F49972861",sizeof(SourceAddress));
    request_hdr_ptr->icd_rev = 6;
    memcpy(&request_hdr_ptr->msga,"1112",sizeof(MSGAscension));
    request_hdr_ptr->rp = 1;
    *op = ReportStatus;
    //Forming timestamp
	memcpy((void *)tstamp,(void *)GetInsideTimeinTimestamp(),sizeof(MessageTimestamp));
	//Forming CRC
	*crc_ptr = calculateCRC32(data);
	outcoming_message_length = sizeof(SMessageHeader) + sizeof(MessageTimestamp) + sizeof(MsgIntegrity);
#ifdef LITTLE_ENDIAN
	convert_big_endian_to_little_endian_and_back(&incoming_message[0],&outcoming_message[0], outcoming_message_length);
	memcpy(data,&outcoming_message[0],outcoming_message_length);
#else
	memcpy(data,&incoming_message[0],outcoming_message_length);
#endif
    *len = sizeof(SMessageHeader) + sizeof(MessageTimestamp) + sizeof(MsgIntegrity);
}

void CheckResponses(u8_t *data, u16_t len)
{
    SMessageHeader *response_hdr_ptr = (SMessageHeader *)&incoming_message[0];
	ACK *response_ack_ptr = (ACK *)(&incoming_message[0] +sizeof(SMessageHeader));
    MsgSolicitedPaylodResponse *response_msg_ptr = (MsgSolicitedPaylodResponse *)(&incoming_message[0] +sizeof(SMessageHeader));
    MessageTimestamp *response_time_ptr = (MessageTimestamp *)&incoming_message[sizeof(SMessageHeader)];
	MessageTimestamp currTime;
	char text_message[100];
	
#ifdef LITTLE_ENDIAN
        incoming_message_length = len;
	convert_big_endian_to_little_endian_and_back(data,&incoming_message[0], incoming_message_length);
	memcpy(data,&outcoming_message[0],outcoming_message_length);
#else
        incoming_message_length = len;
	memcpy(&incoming_message[0],data,len);
#endif

	switch(response_hdr_ptr->mt)
	{
		case ACKMessage:

            sprintf(&text_message[0],"Acknowledgement %c\n", response_ack_ptr->a_d.aw);
            printk(&text_message[0],strlen(&text_message[0]));			
		break;
		case SolictedStatusMessage:
		     sprintf(&text_message[0],"Time Set %d, Time Awake Hours %d\n",response_msg_ptr->ss.ssb.Time_Set_Status,response_msg_ptr->ss.at.at_d);
		     printk(&text_message[0],strlen(&text_message[0]));
		break;
		default: //Hurtbeat
		memcpy((void *)&currTime,(void *)&(response_time_ptr->m_d),sizeof(MessageTimestamp));
		sprintf(&text_message[0],"\r\nTime on BSM Year %d Month %d Day %d Hour %d Minutes %d Seconds %d\n",
		currTime.m_d.year + 30, //Linux start epox 1970, AKUA 2000
		currTime.m_d.month + 1,
		currTime.m_d.day + 1,
		currTime.m_d.hour,
		currTime.m_d.minute,
	    currTime.m_d.seconds);
		printk(&text_message[0],strlen(&text_message[0]));
		break;
	}
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
long int calculateCRC32(unsigned char *data)
{
    	const uint8_t *p = data;
		SMessageHeader *ps = (SMessageHeader *)data; 
		uint32_t size = (uint32_t)sizeof(SMessageHeader) + (uint32_t)ps->ml - (uint32_t)sizeof(MsgIntegrity); 
 		uint32_t crc;
 
 		crc = ~0U;
 		while (size--)
 			crc = ((crc ^ *p++) & 0xFF) ^ (crc >> 8);
 		return (long int)(crc ^ ~0U);
}


