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
#include <iostream>

#define MAXBUF 3072
#define HANDSHAKE_PRINT 1
#define HANDSHAKE_LOOP_PRINT 1



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

    // map will never route to these! you have to edit ctx directly!
    PASSIVE_PRECLOSE,
    ACTIVE_PRECLOSE,

    // active side
    FIN_WAIT_1,
    FORK_CLOSE,

    // passive side
    CLOSE_WAIT,
    LAST_ACK,

    DONE,

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
} context_t;

static bool finsniffer(tcphdr t);

static void send_syn(mysocket_t sd, context_t *ctx);
static void recv_syn_send_synack(mysocket_t sd, context_t *ctx);
static void recv_synack_send_ack(mysocket_t sd, context_t *ctx);
static void recv_ack(mysocket_t sd, context_t *ctx);

static State get_next_state(context_t *ctx, int event);
static State execute_state(context_t *ctx, int event);

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

static void maid_active(mysocket_t sd, context_t *ctx);
static void maid_passive(mysocket_t sd, context_t *ctx);


// this is probably broken, but it needs to be defined in the global scope
std::map<std::pair<State, State>, std::function<void(mysocket_t, context_t*)>> fxn_map = {

        //fxn associated with the start-up. 
    {{CLOSED, CONNECT}, send_syn},
    {{LISTEN, ACCEPT}, recv_syn_send_synack},
    {{CONNECT, ACTIVE_ESTABLISHED}, recv_synack_send_ack}, //
    {{ACCEPT, PASSIVE_ESTABLISHED}, recv_ack}, 

        //fxn associated with the establishment. 
    // idfk how to do this bit Will or Pascal yall are gonna have to handle this
    {{ACTIVE_PRECLOSE, FORK_CLOSE}, maid_active},
    {{PASSIVE_PRECLOSE, CLOSE_WAIT}, maid_passive}, // both of these terminate
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
        /* all of these are horseshit because
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
            */
    }
}

static void send_just_header(mysocket_t sd, context_t *ctx, uint8_t current_flags){
    STCPHeader* send_header = new STCPHeader();
    memset(send_header, 0, sizeof(*send_header));
    send_header->th_seq=ctx->current_sequence_num;
    send_header->th_win=getSize(&ctx->current_buffer);
    send_header->th_flags=current_flags;
    delete send_header;
    stcp_network_send(sd,send_header,sizeof(*send_header));
}

static void recv_just_header(mysocket_t sd, context_t *ctx, uint8_t current_flags){
    STCPHeader* recv_header = new STCPHeader();
    memset(recv_header, 0, sizeof(*recv_header));
    stcp_network_recv(sd, recv_header, sizeof(*recv_header));
    if((recv_header->th_flags & current_flags) != current_flags){
        // error handling?
        ctx->state = ERROR;
        return;
    }
    ctx->tcp_opposite_window_size = recv_header->th_win; 
    ctx->opposite_current_sequence_num = recv_header->th_seq;

}

static void send_syn(mysocket_t sd, context_t *ctx){
    #if HANDSHAKE_PRINT
    std::cout << "SEND SYN" << std::endl;
    #endif

    generate_initial_seq_num(ctx);
    send_just_header(sd,ctx,TH_SYN);

    /*
    STCPHeader* send_header = new STCPHeader();

    memset(send_header, 0, sizeof(*send_header));

    generate_initial_seq_num(ctx);

    send_header->th_seq = ctx->initial_sequence_num;
    send_header->th_win = MAXBUF;
    send_header->th_flags |= TH_SYN;

    stcp_network_send(sd, send_header, sizeof(*send_header));

    ctx->initial_sequence_num = send_header->th_seq;
    ctx->current_sequence_num = send_header->th_seq;

    delete send_header;
    */

}

static void recv_syn_send_synack(mysocket_t sd, context_t *ctx){
    #if HANDSHAKE_PRINT
    std::cout << "RECV SYN SEND SYNACK" << std::endl;
    #endif
    generate_initial_seq_num(ctx);
    recv_just_header(sd,ctx,TH_SYN);
    send_just_header(sd,ctx,TH_SYN|TH_ACK);

    /*
    STCPHeader* recv_header = new STCPHeader();
    STCPHeader* send_header = new STCPHeader();

    memset(recv_header, 0, sizeof(*recv_header));
    memset(send_header, 0, sizeof(*send_header));

    stcp_app_recv(sd, recv_header, sizeof(*recv_header));

    ctx->tcp_opposite_window_size = recv_header->th_win; 
    ctx->tcp_window_size = MAXBUF;

    ctx->opposite_current_sequence_num = recv_header->th_seq;

    if((recv_header->th_flags & TH_SYN) != TH_SYN){
        // error handling?
        ctx->state = ERROR;
    }

    send_header->th_seq = ctx->initial_sequence_num;
    send_header->th_ack = ctx->initial_sequence_num;

    send_header->th_win = MAXBUF;
    send_header->th_flags |= TH_SYN;
    send_header->th_flags |= TH_ACK;

    stcp_network_send(sd, send_header, sizeof(*send_header));
    */
}

static void recv_synack_send_ack(mysocket_t sd, context_t *ctx){
    #if HANDSHAKE_PRINT
    std::cout << "RECV SYNACK SEND ACK" << std::endl;
    #endif
    recv_just_header(sd,ctx,TH_SYN|TH_SYN);
    send_just_header(sd,ctx,TH_ACK);
    
    /*
    STCPHeader* recv_header = new STCPHeader();
    STCPHeader* send_header = new STCPHeader();

    memset(recv_header, 0, sizeof(*recv_header));
    memset(send_header, 0, sizeof(*send_header));

    stcp_app_recv(sd, recv_header, sizeof(*recv_header));

    ctx->tcp_opposite_window_size = recv_header->th_win; 
    ctx->tcp_window_size = MAXBUF;

    if((recv_header->th_flags & TH_ACK) != TH_ACK){
        //some sort of error handling
        // i thiiiiiiiiiiink this is meant to be state = ERROR & then bail because some weird shit happened
        ctx->state = ERROR;
        perror("error in synack");
    }
    */
}
static void recv_ack(mysocket_t sd, context_t *ctx){
    #if HANDSHAKE_PRINT
    std::cout << "RECV ACK" << std::endl;
    #endif

    STCPHeader* recv_header = new STCPHeader();

    memset(recv_header, 0, sizeof(*recv_header));

    stcp_app_recv(sd, recv_header, sizeof(*recv_header));

    ctx->tcp_opposite_window_size = recv_header->th_win; 
    ctx->tcp_window_size = MAXBUF;

    if((recv_header->th_flags & TH_SYN) != TH_SYN && (recv_header->th_flags & TH_ACK) != TH_ACK){
        //some sort of error handling
        ctx->state = ERROR;
        perror("error in ack of syn");
    }
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
    /*
    // this needs to be fixed but i Do Not Understand it so i'm leaving it to one of
    std::map<std::pair<State, State>, std::function<void(mysocket_t, context_t*)>> fxn_map = {

            //fxn associated with the start-up. 
        {{CLOSED, CONNECT}, send_syn},
        {{LISTEN, ACCEPT}, recv_syn_send_synack},
        {{CONNECT, ACTIVE_ESTABLISHED}, recv_synack_send_ack},
        {{ACCEPT, PASSIVE_ESTABLISHED}, recv_ack}, 

            //fxn associated with the establishment. 
    };*/

    unsigned int event; 

    while (!ctx->done)
    {

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

static bool finsniffer(tcphdr* t) {
    return t->th_flags & TH_FIN;
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


