#include <SPI.h>
#include <MFRC522.h>
#include <WiFi.h>
#include <ESP_Mail_Client.h>

#define WIFI_SSID "WIFI NAME"
#define WIFI_PASSWORD "WIFI PASSWORD"
#define SMTP_HOST "smtp.gmail.com"
#define SMTP_PORT 465
#define AUTHOR_EMAIL "YOUR EMAIL "
#define AUTHOR_PASSWORD "YOUR EMAIL APP KEY"
#define RECIPIENT_EMAIL "RECEIVER EMAIL"

SMTPSession smtp;
void smtpCallback(SMTP_Status status);

#define SS_PIN 21
#define RST_PIN 5

MFRC522 rfid(SS_PIN, RST_PIN); // Instance of the class
MFRC522::MIFARE_Key key; 

static int State = LOW; 
String secretValue,alert;

int PIR_pin=2;
int PIRState=LOW;
int val=0;
int buzzPin= 15;
bool flag=false; 

// Init array that will store new NUID 
byte nuidPICC[4];

void sendMail(){ 
    
    Serial.println();
    
    ESP_Mail_Session session;
   
    session.server.host_name = SMTP_HOST;
    session.server.port = SMTP_PORT;
    session.login.email = AUTHOR_EMAIL;
    session.login.password = AUTHOR_PASSWORD;
    session.login.user_domain = "";
    //Message  to alert
    SMTP_Message message;
    message.sender.name = "safe room system";
    message.sender.email = AUTHOR_EMAIL;
    message.subject = "Alert intruder";
    message.addRecipient("Authorized person", RECIPIENT_EMAIL);
    String front="<div><h1>Alert Intruder!</h1><p>";
    String back="</p></div>";
    String htmlMsg = front+alert+back;
    message.html.content = htmlMsg.c_str();
    message.html.content = htmlMsg.c_str();
    message.text.charSet = "us-ascii";
    message.html.transfer_encoding = Content_Transfer_Encoding::enc_7bit;
   /* Connect to server with the session config */
    if (!smtp.connect(&session))
      return;
    /* Start sending Email and close the session */
    if (!MailClient.sendMail(&smtp, &message))
      Serial.println("Error sending Email, " + smtp.errorReason());
}

/* Callback function to get the Email sending status */
void smtpCallback(SMTP_Status status){
  /* Print the current status */
  Serial.println(status.info());

  /* Print the sending result */
  if (status.success()){
    Serial.println("----------------");
    ESP_MAIL_PRINTF("Message sent success: %d\n", status.completedCount());
    ESP_MAIL_PRINTF("Message sent failled: %d\n", status.failedCount());
    Serial.println("----------------\n");
    struct tm dt;

    for (size_t i = 0; i < smtp.sendingResult.size(); i++){
      /* Get the result item */
      SMTP_Result result = smtp.sendingResult.getItem(i);
      time_t ts = (time_t)result.timestamp;
      localtime_r(&ts, &dt);

      ESP_MAIL_PRINTF("Message No: %d\n", i + 1);
      ESP_MAIL_PRINTF("Status: %s\n", result.completed ? "success" : "failed");
      ESP_MAIL_PRINTF("Recipient: %s\n", result.recipients.c_str());
      ESP_MAIL_PRINTF("Subject: %s\n", result.subject.c_str());
    }
    Serial.println("----------------\n");
  }
}  
bool Detect() {
    val = digitalRead(PIR_pin);
    
    digitalWrite(buzzPin,LOW); 
    if (val == HIGH) {         
      Serial.println("Motion Detected !");
      digitalWrite(buzzPin, HIGH);
      delay(100);
      alert="Intruder nears the safe vault";
      sendMail();   
      Serial.println("Mail Sent.");
      delay(1000);     
      return true;
    } 
    else {
      digitalWrite(buzzPin, LOW); 
      delay(300);
      Serial.println("No Motion Detected !");
      return false;
    }
  
}

void setup()
{ 
  pinMode(PIR_pin, INPUT);
  pinMode(buzzPin,OUTPUT);
  
  Serial.begin(9600);
  //wifi
  Serial.print("Connecting to WiFi");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED){
    Serial.print(".");
    delay(200);
  }
  Serial.println("");
  Serial.println("WiFi connected.");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
  Serial.println();
  
  smtp.debug(1);
  smtp.callback(smtpCallback); 
  SPI.begin(); // Init SPI bus
  rfid.PCD_Init(); // Init MFRC522 

  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }

  Serial.println(F("This code scan the MIFARE Classsic NUID."));
  Serial.print(F("Using the following key:"));
  printHex(key.keyByte, MFRC522::MF_KEY_SIZE);
  
}
void loop()
{ digitalWrite(buzzPin,LOW);
// Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  if ( ! rfid.PICC_IsNewCardPresent())
  { 
    return; }
  // Verify if the NUID has been readed
  if ( ! rfid.PICC_ReadCardSerial())
  { 
    return;
  }
  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = rfid.PICC_GetType(rfid.uid.sak);
  Serial.println(rfid.PICC_GetTypeName(piccType));

  // Check is the PICC of Classic MIFARE type
  if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI && 
    piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
    piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
    Serial.println(F("Your tag is not of type MIFARE Classic."));
    return;
  }

  if ( State==LOW || ( rfid.uid.uidByte[0] != nuidPICC[0] || 
    rfid.uid.uidByte[1] != nuidPICC[1] || 
    rfid.uid.uidByte[2] != nuidPICC[2] || 
    rfid.uid.uidByte[3] != nuidPICC[3] ) ) 
  {
      Serial.println(F("A new card has been detected."));

      // Store NUID into nuidPICC array
      for (byte i = 0; i < 4; i++) {
        nuidPICC[i] = rfid.uid.uidByte[i];
      }
      
      Serial.println(F("The NUID tag is:"));
      Serial.print(F("In hex: "));
      printHex(rfid.uid.uidByte, rfid.uid.size);
      Serial.println();
      Serial.print(F("In dec: "));
      printDec(rfid.uid.uidByte, rfid.uid.size);
      Serial.println();
      State=HIGH;
      if(secretValue== "21" && State == HIGH)
      {  
        // authorized card read.  
        //turn on PIR sensor to sense  
        Serial.println(" Now detection system is turned ON ") ;    
        delay(5000); 
        do{
          digitalWrite(buzzPin,LOW);
          Serial.println("Do While loop started....");
          if(secretValue=="21"){
            Serial.println("Authorized user.");
            if(State == HIGH ) 
            {      
              flag=Detect();   
            }
            else{
              //turn off the system
              Serial.println("Turn off the system.");
              State=LOW;
              digitalWrite(buzzPin,LOW);
              break;                                                                      
            }
          }
          else{
              Serial.println("Someone try to enter!");
              alert ="Someone tried to open using unauthorized card! ";
              //send mail to authorized person that unauthorized card deteced
              sendMail();
              State=LOW;
              delay(1000);
              break;
          }
          digitalWrite(buzzPin,LOW);
        }while (!rfid.PICC_IsNewCardPresent() );
          
        flag=rfid.PICC_ReadCardSerial();
        // Store NUID into nuidPICC array
        for (byte i = 0; i < 4; i++) {
           nuidPICC[i] = rfid.uid.uidByte[i];
        }
        Serial.print(F("In dec: "));
        printDec(rfid.uid.uidByte, rfid.uid.size); 
        Serial.println();
        if(secretValue=="21")        
        {
          State=LOW;
          Serial.println("Authorized user card to turn of the system. ");
          if(State == LOW){
            Serial.println("Turn off the system. ");
          }           
        }
        else{
            Serial.println("Someone try to access !");
            alert ="Someone tried to open vault using unauthorized card!";
            //send mail to authorized person that unauthorized card deteced and pause the detection.
            sendMail();
            delay(1000);
            Serial.println("Mail sent- Unauthorized card");          
        }
        Serial.println("---------------------------------------");
        delay(500);
      }
      else
      { 
        Serial.println("Someone try to enter!");
        alert ="Someone tried to open using unauthorized card! ";
        //send mail to authorized person that unauthorized card deteced
        sendMail();
        Serial.println("Mail Sent- Unauthorized card");
        delay(1000);
      }
  }
  else {
    Serial.println(F("----------->>Card read previously."));
    
    Serial.println(F("The NUID tag is:"));
    Serial.print(F("In hex: "));
    printHex(rfid.uid.uidByte, rfid.uid.size);
    Serial.println();
    Serial.print(F("In dec: "));
    printDec(rfid.uid.uidByte, rfid.uid.size);
    Serial.println();
    State=LOW;//turn off the system
    if(secretValue=="21" && State==LOW){
        State=HIGH;
        Serial.println("Anti-Theft System is turned OFF");
        //Don't Detect       
    }
    else{
            State=LOW;
            Serial.println("ACCESS DENIED"); 
    }
  }
  // Halt PICC
  rfid.PICC_HaltA();
  // Stop encryption on PCD
  rfid.PCD_StopCrypto1();
  digitalWrite(buzzPin,LOW);
}
void printHex(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}

void printDec(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], DEC);
    secretValue=buffer[i];
  }
}