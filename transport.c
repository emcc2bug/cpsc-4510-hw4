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

#include <map>
#include <functional>

#define MAXBUF 3072
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
}

int insertWindow(cBuffer* in, char* inString){
    int totalAdded=0;
    for(size_t i = 0;i<strlen(inString);i++){
        if(getSize(in)+1>=MAXBUF){
            break;
        }
    }
    return totalAdded;
}

int calcCheckSum(STCPHeader input){
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

bool checkCheckSum(STCPHeader input){
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
} State;

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    State state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */
} context_t;

static void send_syn(mysocket_t sd, context_t *ctx);
static void recv_syn_send_synack(mysocket_t sd, context_t *ctx);
static void recv_synack_send_ack(mysocket_t sd, context_t *ctx);
static void recv_ack(mysocket_t sd, context_t *ctx);

static State execute_state(context_t *ctx, int event);

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

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

    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    /*ctx->initial_sequence_num =;*/
#endif
}

State get_next_state(context_t *ctx, int event) {

    switch (ctx->state) {
        case CLOSED:
            switch(event){
                case APP_DATA: return CONNECT; 
                default: return ERROR; 
            }
        case LISTEN:
            switch(event){
                case NETWORK_DATA: return ACCEPT;
                default: return ERROR; 
            }
        case CONNECT: 
            switch(event){
                case NETWORK_DATA: return ACTIVE_ESTABLISHED;
                default: return ERROR;
            }
        case ACCEPT: 
            switch(event){
                case NETWORK_DATA: return PASSIVE_ESTABLISHED;
                default: return ERROR;
            }
        default:
            return ERROR;


    }
}

static void send_syn(mysocket_t sd, context_t *ctx){

    // STCPHeader* head = new STCPHeader();

    // head->sport = ctx->

    // stcp_network_send(sd, )
}
static void recv_syn_send_synack(mysocket_t sd, context_t *ctx){

}
static void recv_synack_send_ack(mysocket_t sd, context_t *ctx){

}
static void recv_ack(mysocket_t sd, context_t *ctx){

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

    //maps current, next state to a fxn
    std::map<std::pair<State, State>, std::function<void(mysocket_t, context_t*)>> fxn_map = {

        //fxn associated with the start-up. 
        {{CLOSED, CONNECT}, send_syn},
        {{LISTEN, ACCEPT}, recv_syn_send_synack},
        {{CONNECT, ACTIVE_ESTABLISHED}, recv_synack_send_ack},
        {{ACCEPT, PASSIVE_ESTABLISHED}, recv_ack}, 

        //fxn associated with the establishment. 
    };

    while (!ctx->done)
    {
        unsigned int event; 
        event = stcp_wait_for_event(sd, 0, NULL);

        State next_state = get_next_state(ctx, event);

        if(next_state == ERROR){

            //not sure exactly what should be done here
            exit(1);
        } 

        //execute the event; 
        fxn_map[{ctx->state, next_state}](sd, ctx);

        //advance the state
        ctx->state = next_state;

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



