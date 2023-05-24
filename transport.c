/*
 * transport.c 
 *
 * CPSC4510: Project 3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <cstring>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#include <string>
#include <cstdlib>
#include <ctime>
#include <map>
#include <functional>
#include <iostream>

#define MAXBUF 3072
#define HANDSHAKE_PRINT 0
#define HANDSHAKE_LOOP_PRINT 0
#define ESTABLISHED_PRINT 1
#define FIN_PRINT 1



struct cBuffer{
    int start=0;
    int end=0;
    char buffer[MAXBUF];
};

int getSize(cBuffer* in){
    return (in->end - in->start + MAXBUF) % MAXBUF;
}

int slideWindow(cBuffer* in, int amount){
    if(amount>getSize(in)){
        return -1;
    }
    in->start+=amount;
    in->start=in->start%MAXBUF;
    return 1;
}

char* getWindow(cBuffer* in){
    int size=getSize(in);
    char* out=new char[size];
    if(size!=0){
        out[size-1]=0;
    }
    for(int i = 0;i<size;i++){
        out[i]=in->buffer[(in->start+i)%MAXBUF];
    }
    return out;
}

int insertWindow(cBuffer* in, char* inString){
    int totalAdded=0;
    for(size_t i = 0;i<strlen(inString);i++){
        if(getSize(in)+1>=MAXBUF){
            break;
        }
        in->buffer[(in->end)%MAXBUF]=inString[i];
        in->buffer[(in->end+1)%MAXBUF]=0;
        totalAdded++;
        in->end++;
    }
    return totalAdded;
}

int calcCheckSum(tcphdr input){
    int size=sizeof(tcphdr);
    char * interpretBuffer=(char*)malloc(size);
    memcpy(interpretBuffer,(const void*)&input,size);
    int intermediary=0;
    int total=0;
    for(int i=0;i<size;i++){
        intermediary=0;
        intermediary=intermediary&interpretBuffer[i];
        total=total+intermediary;
    }
    return total;
}

bool checkCheckSum(tcphdr input){
    int sum=input.th_sum;
    input.th_sum=0;
    if(calcCheckSum(input)==sum){
        return true;
    } else {
        return false;
    }
}

typedef enum State {

    LISTEN,
    CLOSED,  

    CONNECT, 
    ACCEPT, 

    ACTIVE_PRECLOSE,
    PASSIVE_PRECLOSE,

    PASSIVE_ESTABLISHED, 
    ACTIVE_ESTABLISHED,

    FORK_CLOSE,

    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    LAST_ACK,

    CLOSING,
    
    ERROR,

    //seems like these names are off limits

    // ECONNREFUSED, 
    // ECONNABORTED,

    ERROR_REFUSED,
    ERROR_ABORTED,


} State;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    State state;   /* state of the connection (established, etc.) */

    tcp_seq initial_sequence_num;
    tcp_seq current_sequence_num;
    tcp_seq opposite_current_sequence_num;

    /* any other connection-wide global variables go here */
    int tcp_opposite_window_size; 
    int tcp_window_size;

    cBuffer current_buffer;
    cBuffer opposite_buffer;

    // used only in close loop smiley
    int fin_ack;
} context_t;

static void send_syn(mysocket_t sd, context_t *ctx);
static void recv_syn_send_synack(mysocket_t sd, context_t *ctx);
static void recv_synack_send_ack(mysocket_t sd, context_t *ctx);
static void recv_ack(mysocket_t sd, context_t *ctx);

static State get_next_state(context_t *ctx, int event);
static State execute_state(context_t *ctx, int event);

static void generate_initial_seq_num(context_t *ctx, bool_t is_active);
static void control_loop(mysocket_t sd, context_t *ctx);

static void maid_active(mysocket_t sd, context_t *ctx);
static void maid_passive(mysocket_t sd, context_t *ctx);

static void close_fork(mysocket_t sd, context_t *ctx);
static void wait_ackfin(mysocket_t sd, context_t *ctx);
static void wait_fin(mysocket_t sd, context_t *ctx);


// this is probably broken, but it needs to be defined in the global scope
std::map<std::pair<State, State>, std::function<void(mysocket_t, context_t*)>> fxn_map = {

        //fxn associated with the start-up. 
    {{CLOSED, CONNECT}, send_syn},
    {{LISTEN, ACCEPT}, recv_syn_send_synack},
    {{CONNECT, ACTIVE_ESTABLISHED}, recv_synack_send_ack}, //
    {{ACCEPT, PASSIVE_ESTABLISHED}, recv_ack}, 

    // establish code handled by regular control loop

    // finish code:
    // im just gonna have both of these go all the way, i think. easier that way.
    {{ACTIVE_PRECLOSE, FORK_CLOSE}, maid_active}, 
    {{PASSIVE_PRECLOSE, CLOSE_WAIT}, maid_passive},
};

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{

    #if HANDSHAKE_PRINT
        std::cout << "IN TRANSPORT_INIT" << std::endl;
    #endif
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx, is_active);

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */
    
    if(is_active){
        ctx->state = CLOSED;
    } else {
        ctx->state = LISTEN; 
    }

    //do the part of the fsm for handshaking
    while(ctx->state != PASSIVE_ESTABLISHED && ctx->state != ACTIVE_ESTABLISHED){

#if HANDSHAKE_LOOP_PRINT
    std::cout << "IN HANDSHAKE LOOP" << std::endl;
#endif

        State next_state = get_next_state(ctx, 0);

        if(next_state == ERROR){

            //not sure exactly what should be done here
            exit(1);
        } 

        //execute the event; 
        fxn_map[{ctx->state, next_state}](sd, ctx);

        //advance the state
        ctx->state = next_state;
    }

    if (ctx->state != ERROR) {
        // end state: connection has been established, handshake is done.
        stcp_unblock_application(sd);
        control_loop(sd, ctx);
    }

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx, bool_t is_active)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    srand(is_active ? time(0)/2 : time(0)/3);
    ctx->initial_sequence_num = rand() % 256;
#endif

    ctx->current_sequence_num = ctx->initial_sequence_num;
}

State get_next_state(context_t *ctx, int event) {

    switch (ctx->state) {
        case CLOSED:
            switch(event){
                // should be refused on connection & aborted on accept, otherwise idfk how this would fail
                default: return CONNECT; 
            }
            break;
        case LISTEN:
            switch(event){
                default: return ACCEPT;
            }
            break;
        case CONNECT: 
            switch(event){
                default: return ACTIVE_ESTABLISHED;
            }
        case ACCEPT: 
            switch(event){
                default: return PASSIVE_ESTABLISHED;
            }

        // this shit is probably not good but this is how i *think* we're meant to do it
        case ACTIVE_ESTABLISHED:
            switch(event){
                case APP_CLOSE_REQUESTED: return FIN_WAIT_1;
                default: return ACTIVE_ESTABLISHED;
            }
        case PASSIVE_ESTABLISHED:
            switch(event){
                default: return PASSIVE_ESTABLISHED;
            }        
        case ACTIVE_PRECLOSE:
            return FORK_CLOSE;
        case PASSIVE_PRECLOSE:
            return CLOSE_WAIT;
        case FIN_WAIT_1:
            // irrelevant
            return FIN_WAIT_1;
        case FIN_WAIT_2:
            switch(event){
                case NETWORK_DATA: return CLOSED; // should be okay because it'll only loop if not done, and we can set done to true.
                default: return FIN_WAIT_2;
            }
        case CLOSE_WAIT:
            switch(event){
                case NETWORK_DATA: return LAST_ACK;
                default: return CLOSE_WAIT;
            }
        case LAST_ACK:
            switch(event){
                // idfk this is probably wrong
                default: return CLOSED;
            }
        default:
            return ERROR;
    }
}

static void send_just_header(mysocket_t sd, context_t *ctx, uint8_t current_flags){
    
    #if HANDSHAKE_PRINT
    std::cout << "SEND HEAD" << std::endl;
    #endif

    STCPHeader* send_header = new STCPHeader();
    memset(send_header, 0, sizeof(STCPHeader));

    //if SYN then you send your initial sequence number
    if(current_flags & TH_SYN){

        #if HANDSHAKE_PRINT
        std::cout << "      INIT SEQ#: " << ctx->current_sequence_num << std::endl;
        #endif

        send_header->th_seq=ctx->current_sequence_num;
    }

    //if ACK you send the next bit of data you expect to recv
    if(current_flags & TH_ACK){
        send_header->th_ack = ctx->opposite_current_sequence_num;
        
        #if HANDSHAKE_PRINT
        std::cout << "      INIT ACK#: " << send_header->th_ack << std::endl;
        #endif
    }

    send_header->th_win=MAXBUF-getSize(&ctx->current_buffer);
    send_header->th_flags=current_flags;
    send_header->th_off = 5; 

    stcp_network_send(sd, send_header, sizeof(STCPHeader), NULL);

    delete send_header;
}

static void recv_just_header(mysocket_t sd, context_t *ctx, uint8_t current_flags){

    #if HANDSHAKE_PRINT
    std::cout << "RECV HEAD" << std::endl;
    #endif

    STCPHeader* recv_header = new STCPHeader();
    
    memset(recv_header, 0, sizeof(STCPHeader));
    
    stcp_network_recv(sd, recv_header, sizeof(STCPHeader));
    
    if((recv_header->th_flags & current_flags) != current_flags){
        // error handling?
        ctx->state = ERROR;
        return;
    }

    #if HANDSHAKE_PRINT
    std::cout << "      RECV FLAGS CORRECT" << std::endl;
    #endif

    //if SYN then you track the opposite seq number
    if(recv_header->th_flags & TH_SYN){
        
        ctx->opposite_current_sequence_num = recv_header->th_seq;

        #if HANDSHAKE_PRINT
        std::cout << "      OPP INIT SEQ#: " << ctx->opposite_current_sequence_num << std::endl;
        #endif
    }

    //TODO: CHNAGE FOR PIPELINE. 
    if(recv_header->th_flags & TH_ACK){

        #if HANDSHAKE_PRINT
        std::cout << "      OPP INIT ACK#: " << recv_header->th_ack << std::endl;
        #endif

        if(recv_header->th_ack != ctx->current_sequence_num + 1){
            //dopped packed
            ctx->state = ERROR;
            return;
        }
    }
    
    ctx->tcp_opposite_window_size = recv_header->th_win;

    delete recv_header;
}

static void send_syn(mysocket_t sd, context_t *ctx){
    send_just_header(sd,ctx,TH_SYN);
}

static void recv_syn_send_synack(mysocket_t sd, context_t *ctx){
    recv_just_header(sd,ctx,TH_SYN);

    //increment when you recv the syn
    ctx->opposite_current_sequence_num++;

    send_just_header(sd,ctx,TH_SYN|TH_ACK);

    
}

static void recv_synack_send_ack(mysocket_t sd, context_t *ctx){
    recv_just_header(sd,ctx,TH_SYN|TH_ACK);

    //increment when you recv the syn
    ctx->opposite_current_sequence_num++;
    //increment when you recv the ack
    ctx->current_sequence_num++;
    
    send_just_header(sd,ctx,TH_ACK);
}
static void recv_ack(mysocket_t sd, context_t *ctx){
    recv_just_header(sd,ctx,TH_ACK);

    //increment when you recv the ack
    ctx->current_sequence_num++;
}

static void recv_sumthin_from_network(mysocket_t sd, context_t *ctx){
    #if ESTABLISHED_PRINT
    std::cout << "RECV FROM NET" << std::endl;
    #endif

    //stores the header and raw data in separate files
    STCPHeader* recv_header = new STCPHeader(); //to store the header after we copy data in
    char* recv_buffer = new char[sizeof(STCPHeader) + STCP_MSS]; //to receive the entire packet
    
    //reads in the data from the network
    int num_read = stcp_network_recv(sd, recv_buffer, sizeof(STCPHeader) + STCP_MSS); //receive from network the entire packet]
    
    int amt_head = (size_t)TCP_DATA_START(recv_buffer);
    int amt_data = num_read - amt_head;

    //reads the data into the header
    memcpy(recv_header,recv_buffer, amt_head); //copy the packet head into the struct which analyzes it
    ctx->fin_ack = 0;
    //analyze struct
    if(recv_header->th_flags&TH_ACK) { 
        ctx->fin_ack = 2;
        #if ESTABLISHED_PRINT
        std::cout << "      RECV ACK" << std::endl;
        std::cout << "      ACK#:" << recv_header->th_ack << std::endl;
        #endif

        //TODO: not sure if this works
        //then record how much data has been received by the other
        slideWindow(&ctx->current_buffer,recv_header->th_ack-ctx->current_sequence_num);
        //and record it in the sequence num
        ctx->tcp_opposite_window_size+=recv_header->th_ack-ctx->current_sequence_num;
        //no the seq_number are adjusted when stuff is sent. 
        // ctx->current_sequence_num=recv_header->th_ack;

    } else if(recv_header->th_flags&TH_FIN) { 
        ctx->fin_ack = 1;
        #if ESTABLISHED_PRINT
        std::cout << "      RECV FIN" << std::endl;
        #endif
        if (ctx-> state == PASSIVE_ESTABLISHED || ctx->state == ACTIVE_ESTABLISHED)
            ctx->state = PASSIVE_PRECLOSE;
        ctx->opposite_current_sequence_num += 1;
        send_just_header(sd,ctx,TH_ACK); 

    } if (amt_data > 0) { //otherwise access the data part of the packet if it exists
        
        #if ESTABLISHED_PRINT
        std::cout << "      RECV DATA" << std::endl;
        std::cout << "      RECV SEQ NUMBER (MATCH OPP): " << recv_header->th_seq << std::endl;
        //prints everything but the end of line character
        std::cout << "      DATA: " << std::string(&recv_buffer[amt_head]).substr(0, amt_data - 2) << std::endl;
        std::cout << "      AMT: " << amt_data << std::endl;
        #endif
        
        //TODO: PASCAL FIGURE THIS OUT
        insertWindow(&ctx->opposite_buffer,recv_buffer); //record that data was given to us
        
        //increments the opposite sequence number for the ack
        ctx->opposite_current_sequence_num += amt_data; //record the sequence number
        
        //send an ack
        send_just_header(sd,ctx,TH_ACK); 

        //send the data to client
        stcp_app_send(sd, &recv_buffer[amt_head], amt_data); 

        //TODO: PASCAL FIGURE THIS OUT
        slideWindow(&ctx->opposite_buffer,num_read); //record that data was sent up
    }
    delete recv_header;
}

static void recv_sumthin_from_app(mysocket_t sd, context_t *ctx){
    
    #if ESTABLISHED_PRINT
    std::cout << "RECV FROM APP" << std::endl;
    #endif
    
    //NEED TO CHECK THE RECV HAS ENOUGH ROOM IN BUFFER

    char* recv_buffer = new char[STCP_MSS]; //temp recv buffer
    memset(recv_buffer,'\0',STCP_MSS);

    //receive the data from the app
    //size_t num_read = stcp_app_recv(sd, (void*)recv_buffer, STCP_MSS);
    size_t num_read = stcp_app_recv(sd, (void*)recv_buffer, MIN(STCP_MSS-1,MAXBUF-getSize(&ctx->current_buffer)));

    //put it in the buffer to be tracked
    insertWindow(&ctx->current_buffer,recv_buffer); 

    //make sure the window size is tracked too, otherwise we could potentially send more data than the app can hold
    ctx->tcp_opposite_window_size-=num_read;

    #if ESTABLISHED_PRINT
    //print but no end line or carriage returns
    std::cout << "      RECV: " << std::string(recv_buffer, num_read).substr(0, num_read) << std::endl;
    #endif
    
    #if ESTABLISHED_PRINT
    std::cout << "      CURRENT SEQ NUM:" << ctx->current_sequence_num << std::endl;
    #endif

    STCPHeader* send_header = new STCPHeader();
    memset(send_header, 0, sizeof(STCPHeader));

    send_header->th_win = (uint16_t) MAXBUF-getSize(&ctx->current_buffer);
    send_header->th_flags = 0;
    send_header->th_seq=ctx->current_sequence_num;
    send_header->th_off = 5; 

    stcp_network_send(sd, (void*)send_header, sizeof(STCPHeader), (void*)recv_buffer, num_read, NULL);

    delete send_header;

    //advances our seq number
    ctx->current_sequence_num += ctx->current_sequence_num+num_read;
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);

    unsigned int event; 
  
    #if ESTABLISHED_PRINT
    std::cout << "HANDSHAKE COMPLETE!" << std::endl;
    std::cout << "SEQ NUM: " << ctx->current_sequence_num << std::endl;
    std::cout << "OPP SEQ NUM: " << ctx->opposite_current_sequence_num << std::endl;
    #endif


    // ESTABLISHED state
    while (ctx->state == PASSIVE_ESTABLISHED || ctx->state == ACTIVE_ESTABLISHED)
    {
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        if(event & APP_DATA){
            recv_sumthin_from_app(sd, ctx);
        } else if (event & NETWORK_DATA){
            recv_sumthin_from_network(sd, ctx);
        } else if (event & APP_CLOSE_REQUESTED) {
            ctx->state = ACTIVE_PRECLOSE;
        }
    }
    while (!ctx->done) {
        #if FIN_PRINT
            std::cout << "ENTERING CLOSE LOOP" << std::endl;
        #endif
        State next_state = get_next_state(ctx, 0);

        fxn_map[{ctx->state, next_state}](sd, ctx);
        #if FIN_PRINT
            std::cout << "SHUTTING DOWN... " << std::endl;
        #endif
    }
}

static void maid_active(mysocket_t sd, context_t *ctx) {
    // sends a fin packet. we're not waiting for it to close because that's fin_wait_1's problem
    send_just_header(sd, ctx, TH_FIN);
    #if FIN_PRINT
        std::cout << "SENT FIN FROM ACTIVE" << std::endl;
    #endif
    close_fork(sd, ctx);

}
static void maid_passive(mysocket_t sd, context_t *ctx) {
    // we've already signalled application to expect EOF & ack'd it, now we send FIN & wait for last ack
    send_just_header(sd, ctx, TH_FIN);
    #if FIN_PRINT
        std::cout << "SENT FIN FROM PASSIVE" << std::endl;
    #endif
    wait_ackfin(sd, ctx);
}

static void close_fork(mysocket_t sd, context_t *ctx) {
    stcp_wait_for_event(sd, NETWORK_DATA, NULL);
    // this must be either an ACK or a FIN and anything else is a sign that Something Has Gone Terribly Wrong
    recv_sumthin_from_network(sd, ctx);
    // fin has been received before ack of fin, wait for last ack then bail
    if (ctx->fin_ack == 1) { 
        #if FIN_PRINT
            std::cout << "GOT FIN, WAITING ACK" << std::endl;
        #endif
        stcp_fin_received(sd);
        wait_ackfin(sd, ctx);
    } 
    // ack received, enter FIN_WAIT_2
    else {
        #if FIN_PRINT
            std::cout << "GOT ACK, WAITING FIN" << std::endl;
        #endif
        wait_fin(sd, ctx);
        ctx->state = FIN_WAIT_2;
    }
}
static void wait_fin(mysocket_t sd, context_t *ctx) {
    // wait for fin, ACK handled by function call, then set done = true and bail
    unsigned int x = stcp_wait_for_event(sd, ANY_EVENT, NULL);
    #if FIN_PRINT
        std::cout << "EVENT TYPE: " << x << std::endl;
    #endif
    recv_sumthin_from_network(sd, ctx);
    if (ctx->fin_ack != 1) { // something has terribly gone wrong
        perror("????? error in FIN_WAIT_2 section");
    } else {
        stcp_fin_received(sd);
    }
    #if FIN_PRINT
        std::cout << "ALL DONE!" << std::endl;
    #endif
    ctx->done = true;
}

static void wait_ackfin(mysocket_t sd, context_t *ctx) {
    stcp_wait_for_event(sd, 2, NULL);
    #if FIN_PRINT
        std::cout << "DOOR STUCK" << std::endl;
    #endif
    recv_sumthin_from_network(sd, ctx);

    #if FIN_PRINT
        if (ctx->fin_ack != 2) 
            std::cout<< "OH NO " << ctx->fin_ack << std::endl;
        std::cout << "ALL DONE!" << std::endl;
    #endif
    ctx->done = true;
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

