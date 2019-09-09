/*This data protocol reflects "Secure Hybrid Composite Intermodal Container Project"
 * 
 */
#include <zephyr/types.h>
/*SHCIC Message Header*/
typedef unsigned char SourceDeviceType;
typedef unsigned char MSGLength;
typedef unsigned char MSGType;
typedef union {
	unsigned char sa[6];
	unsigned char sa_data[6];  
} SourceAddress;
typedef union {
	unsigned char da[6];
	unsigned char da_data[6];
} DestinationAddress;
typedef unsigned char ICDRev;
typedef union {
	unsigned char msga[4];
	unsigned char msga_data[4];
}  MSGAscension;
typedef unsigned char RoutingPriority;

typedef struct {
	SourceDeviceType st;
	MSGType mt;
	MSGLength ml;
	SourceAddress sa;
	DestinationAddress da;
	ICDRev icd_rev;
	MSGAscension msga;
	RoutingPriority rp;
} SMessageHeader;

/*3.6.1.2 Message Device Type Codes*/ 
typedef enum {
	BSM=0x80,
	SensorController=0x81,
	C2Server=0x88,
	KeyMgmtServer=0x89
} DeviceType;

/*3.6.1.3 Message Type Codes*/
typedef enum {
	SolictedStatusMessage=0x80,
	DeviceEventLogRecord=0x81,
	UnsolictedStatusMessage=0x82,
	ACKMessage=0x83,
	SecurityDeviceMaintMessage_0=0x90,
	SecurityDeviceMaintMessage_1=0x91,
	SecurityDeviceMaintMessage_2=0x92,
	SecurityDeviceMaintMessage_3=0x93,
	SecurityDeviceMaintMessage_4=0x94,
	SecurityDeviceMaintMessage_5=0x95,
	SecurityDeviceMaintMessage_6=0x96,
	SecurityDeviceMaintMessage_7=0x97,
	SecurityDeviceMaintMessage_8=0x98,
	SecurityDeviceMaintMessage_9=0x99,
	SecurityDeviceMaintMessage_A=0x9A,
	SecurityDeviceMaintMessage_B=0x9B,
	SecurityDeviceMaintMessage_C=0x9C,
	SecurityDeviceMaintMessage_D=0x9D,
	SecurityDeviceMaintMessage_E=0x9E,
	SecurityDeviceMaintMessage_F=0x9F,
	DeviceCommand=0xC1,
	KeyMgmtRekey_0=0xE0,
	KeyMgmtRekey_1=0xE1,
	KeyMgmtRekey_2=0xE2,
	KeyMgmtRekey_3=0xE3,
	KeyMgmtRekey_4=0xE4,
	KeyMgmtRekey_5=0xE5,
	KeyMgmtRekey_6=0xE6,
	KeyMgmtRekey_7=0xE7,
	KeyMgmtRekey_8=0xE8,
	KeyMgmtRekey_9=0xE9,
} MessageTypeCode;

/* 3.6.2.1 Device Command Message */	
typedef union {
	unsigned char data[25];
	SMessageHeader smh;
} UniversalMSGHeader;
typedef enum {
	ReportStatus=0x1,
	RunDiagnostics=0x2,
	SetTime=0x3,
	ARM=0x4,
	PairCommand=0x5,
	UnPairCommand=0x6,
	DISARM=0x80,
	SendAllEventLog=0xA4,
	EraseEventLog=0xA5,
	ConfigureSensor=0x8
} OP_Code;
typedef unsigned char OP_code_command;
typedef struct {
	unsigned char month;
	unsigned char day;
	uint16_t      year; //Year starting 2000
	unsigned char hour;
	unsigned char minute;
	unsigned char seconds;
	unsigned char hundr_of_seconds;
}   MessageTimestamp_d;
typedef union {
	unsigned char data[8];
	MessageTimestamp_d m_d;
} MessageTimestamp;
typedef unsigned char SynchTime_d[8];
typedef union {
	unsigned char data[8];
	SynchTime_d  s_d;
} SynchTime;
typedef unsigned char SensorToEnable_d[8];
typedef union {
	unsigned char data[8];
	SensorToEnable_d s_d;
} SensorToEnable;
typedef unsigned char unconditional_par;
typedef enum {
	unconditional_yes=0xFF
} unconditional_value;
typedef unsigned char CSD_SD_MAC_d[8];
typedef union {
	unsigned char data[8];
	CSD_SD_MAC_d csd_d;
} CSD_SD_MAC;
typedef unsigned char BSM_Sensor_MAC_d[8];
typedef union {
	unsigned char data[8];
	BSM_Sensor_MAC_d b_d;
} BSM_Sensor_MAC;
typedef unsigned char BSM_Sensor_Type;
typedef unsigned char BSM_Sensor_UID_d[8];
typedef union {
	unsigned char data[8];
	BSM_Sensor_UID_d b_d;
} BSM_Sensor_UID;
typedef unsigned char SensorToDisable_d[8];
typedef union {
	unsigned char data[8];
	SensorToDisable_d s_d;
} SensorToDisable;
typedef unsigned char ConfigurationParam;
typedef uint32_t MsgIntegrity_d;
typedef union {
	unsigned char data[8];
	MsgIntegrity_d  m_d;
} MsgIntegrity;
typedef struct {
	MessageTimestamp mt;
} ReportStatusPayload;
typedef struct {
	MessageTimestamp mt;
} RunDiagnosticsPayload;
typedef struct {
	MessageTimestamp mt;
	SynchTime st;
} SetTimePayload;
typedef struct {
	MessageTimestamp mt;
	SensorToEnable se;
} ARMPayload;
typedef struct {
	MessageTimestamp mt;
	CSD_SD_MAC csd;
	BSM_Sensor_MAC bsmm;
	BSM_Sensor_Type bsmt;
	BSM_Sensor_UID bsmu;
} PairCommandPayload;
typedef struct {
	MessageTimestamp mt;
} UnPairCommandPayload;
typedef struct {
	MessageTimestamp mt; 
	SensorToDisable sd;
} DISARMPayload;
typedef struct {
	MessageTimestamp mt;
} SendAllEventLogPayload;
typedef struct {
	MessageTimestamp mt;
} EraseEventLogPayload;
typedef struct {
	MessageTimestamp mt;
	ConfigurationParam cp;
} ConfigureSensorPayload;
typedef union {
	unsigned char data[94];
	ReportStatusPayload rsp;
	RunDiagnosticsPayload rdp;
	SetTimePayload stp;
	ARMPayload armp;
	PairCommandPayload pcp;
	UnPairCommandPayload upcp;
	DISARMPayload darmp;
	SendAllEventLogPayload sael;
	EraseEventLogPayload eelp;
	ConfigureSensorPayload csp;
} MSGPayload;

typedef struct {
	UniversalMSGHeader umh;
	MSGPayload mp;
	MsgIntegrity mi;
}  DeviceCommandMessage;

typedef struct {
	unsigned Diag_Status : 1;
	unsigned Pwr_Status : 1;
	unsigned Pairing_Status : 1;
	unsigned Arming_Status : 1;
	unsigned Time_Set_Status : 1;
	unsigned unused : 3;
} SolicitedStatusBits;

typedef unsigned char Alarm_Status;

typedef uint8_t Awake_Time_d;

typedef union {
	unsigned char data[2];
	Awake_Time_d at_d;
} Awake_Time;
 
typedef uint16_t Rekey_Counter_d;

typedef union {
	unsigned char data[4];
	Rekey_Counter_d rc_d;
} Rekey_Counter;

typedef uint16_t ACK_Ascension_d;

typedef union {
	unsigned char data[4];
	ACK_Ascension_d aa_d;
} ACK_Ascension;
 
/* 3.6.2.2.1 Solicited Status Message */
typedef struct {
	SolicitedStatusBits ssb;
	Alarm_Status as;
	Awake_Time at;
	Rekey_Counter rc;
	ACK_Ascension aa;
} Status_Summary;

typedef unsigned char Panel_Alarm_Data_d[7];

typedef union {
	unsigned char data[7];
	Panel_Alarm_Data_d pad_d;
} Panel_Alarm_Data;

typedef unsigned char Door_State;

typedef unsigned char Pwr_Level;

typedef unsigned char Reserved1[12];

typedef struct {
	Panel_Alarm_Data pad;
	Door_State ds;
	Pwr_Level pl;
	Reserved1 r1;
} BDS_Status_Details;

typedef struct {
	Reserved1 r1;
} Alarm_Details;

typedef union {
	Status_Summary ss;
	BDS_Status_Details bsd;
	Alarm_Details ad;
	unsigned char data[94];
} MsgSolicitedPaylodResponse;

/* 3.6.2.4.1 Acknoledgement message */
typedef uint16_t ACK_Asc;
typedef unsigned char ACK_WQ;
typedef struct {
	ACK_Asc aa;
	ACK_WQ aw;
} ACK_d;
typedef union {
	unsigned char data[5];
	ACK_d a_d;
} ACK;

/* 3.6.2.5.1 Device Event Log Message*/

typedef unsigned char AscensionEventLogRequest;
typedef unsigned char EventType;
typedef uint32_t EventTime_d;
typedef union {
	unsigned char data[8];
	EventTime_d et_d;
} EventTime;
typedef unsigned char LastRequestRecord;

typedef unsigned char Panel_Alarm_Data_Dflt_d[80];
typedef union {
	unsigned char data[80];
	Panel_Alarm_Data_Dflt_d padd_d;
} Panel_Alarm_Data_Dflt;

typedef struct {
	AscensionEventLogRequest aelr;
	EventType etp;
	EventTime et;
	LastRequestRecord lrr;
	Panel_Alarm_Data_Dflt padd;
} MsgPayloadEventLogResponse;


typedef union {
	MsgSolicitedPaylodResponse mspr;
	ACK ack;
	MsgPayloadEventLogResponse mpelr;
} MsgPaylodResponse;


void data_to_send(u8_t *data,u16_t *len);
void data_handler_rx(u8_t *data,u16_t len);