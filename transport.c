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

#include <cstdlib>
#include <ctime>
#include <map>
#include <functional>
#include <iostream>

#define MAXBUF 3072
#define HANDSHAKE_PRINT 1
#define HANDSHAKE_LOOP_PRINT 0
#define ESTABLISHED_PRINT 1



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

    PASSIVE_ESTABLISHED, 
    ACTIVE_ESTABLISHED,

    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    LAST_CALL,

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
} context_t;



static void send_syn(mysocket_t sd, context_t *ctx);
static void recv_syn_send_synack(mysocket_t sd, context_t *ctx);
static void recv_synack_send_ack(mysocket_t sd, context_t *ctx);
static void recv_ack(mysocket_t sd, context_t *ctx);

static State get_next_state(context_t *ctx, int event);
static State execute_state(context_t *ctx, int event);

static void generate_initial_seq_num(context_t *ctx, bool_t is_active);
static void control_loop(mysocket_t sd, context_t *ctx);


// this is probably broken, but it needs to be defined in the global scope
std::map<std::pair<State, State>, std::function<void(mysocket_t, context_t*)>> fxn_map = {

        //fxn associated with the start-up. 
    {{CLOSED, CONNECT}, send_syn},
    {{LISTEN, ACCEPT}, recv_syn_send_synack},
    {{CONNECT, ACTIVE_ESTABLISHED}, recv_synack_send_ack}, //
    {{ACCEPT, PASSIVE_ESTABLISHED}, recv_ack}, 

        //fxn associated with the establishment. 
    // idfk how to do this bit Will or Pascal yall are gonna have to handle this
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
    else { // maybe idk

        //can't return from a void silly goose

        // if (is_active) return ECONNREFUSED;
        // else return ECONNABORTED;
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
                // this *shouldn't* change state here, it should change state in response to
                // seeing a FIN packet. so i don't think we do anything here.
            }
        case FIN_WAIT_1:
            switch(event){
                case NETWORK_DATA: return FIN_WAIT_2;
                // maybe? maybe not? i think we're meant to switch state in response to getting an ACK for our *FIN packet specifically*, but also...
                default: return FIN_WAIT_1;
            }
        case FIN_WAIT_2:
            switch(event){
                case NETWORK_DATA: return CLOSED; // should be okay because it'll only loop if not done, and we can set done to true.
                default: return FIN_WAIT_2;
            }
        case CLOSE_WAIT:
            switch(event){
                case NETWORK_DATA: return LAST_CALL;
                default: return CLOSE_WAIT;
            }
        case LAST_CALL:
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
        send_header->th_ack=ctx->opposite_current_sequence_num+1;
        
        #if HANDSHAKE_PRINT
        std::cout << "      INIT ACK#: " << send_header->th_ack << std::endl;
        #endif
    }

    send_header->th_win=getSize(&ctx->current_buffer);
    send_header->th_flags=current_flags;
    send_header->th_off = 5; 

    stcp_network_send(sd,send_header,sizeof(STCPHeader), NULL);

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
    ctx->opposite_current_sequence_num = recv_header->th_seq;

    delete recv_header;
}

static void send_syn(mysocket_t sd, context_t *ctx){
    send_just_header(sd,ctx,TH_SYN);
}

static void recv_syn_send_synack(mysocket_t sd, context_t *ctx){
    recv_just_header(sd,ctx,TH_SYN);
    send_just_header(sd,ctx,TH_SYN|TH_ACK);
}

static void recv_synack_send_ack(mysocket_t sd, context_t *ctx){
    recv_just_header(sd,ctx,TH_SYN|TH_ACK);
    send_just_header(sd,ctx,TH_ACK);
}
static void recv_ack(mysocket_t sd, context_t *ctx){

    recv_just_header(sd,ctx,TH_ACK);
}

static void recv_data_from_network(mysocket_t sd,context_t *ctx){

    #if ESTABLISHED_PRINT
    std::cout << "RECV FROM NET" << std::endl;
    #endif

    char recv_buffer[MAXBUF]; //temp buffer

    //TODO: needs to be remaining buffer
    ssize_t num_read = stcp_network_recv(sd, (void*)&recv_buffer, sizeof(recv_buffer));

    //null terminating
    recv_buffer[num_read] = '\0';

    //memcpy for ring buffer
    insertWindow(&ctx->opposite_buffer,recv_buffer);

    //now the next byte to be recved, currently needs to be acked
    ctx->opposite_current_sequence_num += num_read;

    //ack that we received
    send_just_header(sd,ctx,TH_ACK);

    //send the data to the app
    stcp_app_send(sd,recv_buffer,num_read);

    //move the ring buffer to receive new data
    slideWindow(&ctx->opposite_buffer,num_read);
}

static void recv_sumthin_from_network(mysocket_t sd, context_t *ctx){
    STCPHeader * recv_header = new STCPHeader(); //to store the header after we copy data in
    char * recv_buffer = new char[sizeof(STCPHeader)]; //to receive the entire packet
    int num_read = stcp_network_recv(sd,recv_buffer, sizeof(recv_buffer)); //receive from network the entire packet
    memcpy(recv_header,recv_buffer,TCP_DATA_START(recv_buffer)); //copy the packet head into the struct which analyzes it

    //analyze struct
    if((recv_header->th_flags&TH_ACK)==TH_ACK){ //if it is an ack
        slideWindow(&ctx->current_buffer,recv_header->th_ack-ctx->current_sequence_num); //then record how much data has been received by the other
        ctx->current_sequence_num=recv_header->th_ack; //and record it in the sequence num
    } else if((recv_header->th_flags&TH_FIN)==TH_FIN) { //otherwise if it receives an unsolicited fin
        // ctx->state=PASSIVE_PRECLOSE; /////////////////////////////////////////////////////// change for fsm, evelyn
    } else { //otherwise access the data part of the packet
        insertWindow(&ctx->opposite_buffer,recv_buffer); //record that data was given to us
        ctx->current_sequence_num=ctx->current_sequence_num+num_read; //record the sequence number
        send_just_header(sd,ctx,TH_ACK); //send an acknowledgement, based off the prerecorded sequence num
        stcp_app_send(sd,recv_buffer,num_read); //send the data up
        slideWindow(&ctx->opposite_buffer,num_read); //record that data was sent up
    }
    delete recv_header;
}

static void recv_sumthin_from_app(mysocket_t sd, context_t *ctx){
    
    #if ESTABLISHED_PRINT
    std::cout << "RECV FROM APP" << std::endl;
    #endif
    
    char recv_buffer[STCP_MSS]; //temp recv buffer

    //receive the data from the app
    size_t num_read = stcp_app_recv(sd,recv_buffer,STCP_MSS);

    //null terminate
    recv_buffer[num_read] = '\0';

    //memcpy for the ring buffer
    insertWindow(&ctx->current_buffer,recv_buffer);

    //create the header
    STCPHeader* send_header = new STCPHeader();
    memset(send_header, 0, sizeof(STCPHeader));

    //NEED TO CHECK THE RECV HAS ENOUGH ROOM IN BUFFER

    //seq num is first byte in packet
    send_header->th_seq=ctx->current_sequence_num;
    send_header->th_off=5;
    send_header->th_win=(uint16_t) getSize(&ctx->current_buffer);

    //sends it over the network
    stcp_network_send(sd, send_header, sizeof(STCPHeader), recv_buffer, num_read, NULL);



    //advances our seq number
    ctx->current_sequence_num=ctx->current_sequence_num+num_read;
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

    while (!ctx->done)
    {

        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        if(event & APP_DATA){
            recv_sumthin_from_app(sd, ctx);
        } else if (event & NETWORK_DATA){
            recv_sumthin_from_network(sd, ctx);
        }

        // } else (event & APP_CLOSE_REQUESTED){
        //     //evelyn's job
        // }

        // unsigned int event;

        // /* see stcp_api.h or stcp_api.c for details of this function */
        // /* XXX: you will need to change some of these arguments! */
        // event = stcp_wait_for_event(sd, 0, NULL);

        // /* check whether it was the network, app, or a close request */
        // if (event & APP_DATA)
        // {
        //     /* the application has requested that data be sent */
        //     /* see stcp_app_recv() */
        // }

        // /* etc. */
    }
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


