//===================================================================================================================================================
// EDT2UDP - Capture raw RRI receiver fibre data, unpack, and copy to UDP
// streams to the relevant data consumers
//
// Author(s)  BWC Brian Crosse brian.crosse@curtin.edu.au
// Commenced 2018-07-04
#define BUILD 39
//
// 3.00e-039    2022-11-22 LAW  Disable kicking EDT card automatically.
//
// 3.00d-038    2022-06-24 LAW  Multicast stalled indicator in health packet. Multicast suppressed for medconv01:1:2 for future debugging purposes.
//
// 3.00c-037    2022-06-10 LAW  Configuration file loader
//
// 3.00c-036    2022-05-10 LAW  Receiver 4 handles tile 31-38
//
// 3.00b-035    2022-01-19 BWC  Change to long baseline configuration
//
// 3.00a-034    2021-11-10 BWC  Make 'kick' edt also open and close the port.
//				Add support for health packets to show 'unusable','junk','badsync' & 'lostsync' counts
//				Automatically kick the edt card if the arrival time for the second's data is late two times in a row.
//
// 3.00a-033    2021-10-26 BWC  Change medconv01 multicast interface details for the new medconv01
//
// 3.00a-032    2021-10-22 BWC  Fix sign error in "Possible recovery" logic
//				=IF((AI50-1130496)<0,AI50-1130496+12*1024*1024,AI50-1130496) to keep track of w2f offsets
//
// 3.00a-031    2021-10-20 BWC  Improve health info and provide more details about EDT blocks that lose sync.
//
// 3.00a-030    2021-10-13 BWC  Send health data packets to 224.0.2.2:8003
//
// 3.00a-029    2021-10-11 BWC  Add logging on transmission of a good second from the flip2buff thread
//
// 3.00a-028    2021-10-07 BWC  Change log output for easier receiver startup status checking.  More 'fflush(stdout);'
//				Add support for a SIGUSR1 to force an EDT card ring buffer reset
//
// 3.00a-027    2021-09-14 BWC  Update all the IP addresses for medconv01 -> medconv10
//
// 3.00a-026    2021-08-23 BWC  Add timing information to help identify receivers which are not correctly programmed
//
// 3.00a-025    2021-05-06 BWC  Change array config to Short baseline
//
// 3.00a-024    2021-02-15 BWC  Remove redirection of coarse channels
//
// 3.00a-023    2021-01-08 BWC  Update rri2rf_input[] table to include 'RFIpole' on LONG BASELINE config
//				Change redirection added in build 22 to '(CC09 will be redirected to where CC10 also goes)'
//
// 3.00a-022    2020-11-03 BWC  Force two coarse channels to same destination multicast address.  (CC11 will be redirected to where CC12 also goes)
//
// 3.00a-021    2019-12-11 BWC  Alter debug file writes to help diagnose rec05. Fix build number not incremented in 19/20
//
// 3.00a-020    2019-10-31 BWC  Change from long baseline to short baseline configuration
//
// 3.00a-019    2019-06-07 BWC  Be smarter about sleeping if waiting for 5 to 8 bit conversions to take place.  This replaces a spin lock with a usleep()
//
// 3.00a-018    2019-05-28 BWC  Split 5 to 8 bit conversion work into 2 threads.
//
// 3.00a-017    2019-04-03 BWC  Set up for 6 channels, being 9 to 14 inclusive (gpubox09 to gpubox14).  Change vcs port to the 2nd 10Gb port direct to Cisco.  Use long baseline rf_inputs
//
// 3.00a-016    2019-03-19 BWC  Support a reduced set of channels for output.  eg first 4 of 8.
//
// 3.00a-015    2019-03-18 BWC  Rate Limiting based on number of packets made.
//
// 3.00a-014    2019-03-15 BWC  Debug build
//
// 3.00a-013    2019-03-05 BWC  Merge 5bit and 8bit buffer metadata arrays and pin 8 bit buffer to bottom 4 bits of GPS_time
//
// 3.00a-012    2019-03-04 BWC  Numerous changes to udp transmissions.  Non-compilable, interim version
//
// 3.00a-011    2018-11-05 BWC  Shift in 5 to 8 bit promotion
//                              Change udp packet specification to send tile_id
//
// 3.00a-010    2018-07-04 BWC  Fork code from existing 3Pip software.
//===================================================================================================================================================
// Capture UDP packets into a temporary, user space buffer and then sort/copy/process them into some output array
//
// Author(s)  BWC Brian Crosse brian.crosse@curtin.edu.au
// Commenced 2017-05-25
//
// 2.03e-071    2021-12-02 GJS  Update to swap mwax05 back into getting channel 5.
//
// 2.03d-070    2021-11-09 GJS  Update to add breakthrough listen compute node to the channel mapping struct
//
// 2.03c-069    2021-10-26 BWC  Change mwax05 to CC25 (ie stop it from seeing data)
//                              Yet to do: "Also grab RAWSCALE from metafits and stick it in as is into the PSRDADA header.  It’s a decimal value (float?)"
//
// 2.03b-068    2021-10-25 BWC  Handle disappearance (and later restart) of edp packets better
//                              Change RECVMMSG_MODE back to MSG_WAITFORONE so VMA can work more efficiently
//                              Add logging of the number of free file available when about to write out a sub file
//                              Add version and build to PSRDADA header
//
// 2.03a-067    2021-10-20 BWC  Modified default channels to be 1-26 (with a copy of CC10 on mwax25 because mwax10 is in Perth)
//
// 2.02z-066    2021-10-07 GJS  Modified default channels to be 1-12
//
// 2.02y-065    2021-10-06 GJS  Modified default channels for mwax25 and 26
//
// 2.02y-064    2021-10-05 BWC  Trap SIGTERM in addition to SIGINT for shutdown requests
//
// 2.02x-063    2021-10-05 BWC  Change default channels for mwax25 and mwax26
//
// 2.02w-062    2021-10-05 BWC  Fix minor bug with affinity being set differently on mwax15
//
// 2.02v-061    2021-09-22 BWC  Add all genuine mwax servers (mwax01 to mwax26) into config
//
// 2.02u-060    2021-08-19 BWC  Add genuine mwax01 into config and move older servers to 192.168.90.19x addresses for the voltage network
//
// 2.02t-059    2021-03-19 BWC  Check /dev/shm/mwax directory exists to prevent crash
//                              Check /vulcan/metafits directory exists to prevent crash
//                              Add -c coarse channel override command on command line
//                              Included some delay tracking stuff (See below)
//                              Added source offset to packet address during copy
//                              Revert hardcoded sections to Short Baseline.
//                              Update names of mwax servers to mwax106 etc.
//                              Increase the size of the ip string to prevent a compiler warning
//
// 2.02s-058    2021-02-15 BWC  Update layout config for mwax01-mwax07
//
// 2.02r-057    2021-01-11 BWC  Update layout config to Long Baseline *with* RFIpole
//                              Alter the config options to be better suited to CC10 being 256T data volume
//
// 2.02q-056    2021-01-04 BWC  If the FILENAME in the metafits contains 'mwax_vcs' or 'mwax_corr' put in the relevant modes
//                              Update the server config
//
// 2.02p-055    2020-11-25 BWC  Force the MODE to NO_CAPTURE unless the FILENAME in the metafits contains 'HTR'
//
// 2.02n-054    2020-11-19 BWC  Don't set CPU affinity except for on mwax07 and mwax0a
//
// 2.02m-053    2020-11-12 BWC  To aid in debugging, convert NO_CAPTURES to HW_LFILES
//
// 2.02k-052    2020-11-05 BWC  Make "MSG_DONTWAIT" vs "MSG_WAITFORONE" a #define option
//                              Increase the size of the UDP buffers to 8x1024x1024
//                              Print more debug info at closedown
//
// 2.02j-051    2020-11-03 BWC  Add config lines for mwax07 and mwax0a to make it easy to switch coarse channels
//                              Add fflush(stdout) after all relevant printf lines for debug file output
//
// 2.02i-050    2020-10-29 BWC  Make changes to the recvmmsg code to hopefully improve performance.
//
// 2.02h-049    2020-10-23 BWC  Add command line debug option to set debug_mode on. (ie write to .free files instead of .sub files)
//
// 2.02g-048    2020-10-21 BWC  Add selectable cpu affinity per thread
//
// 2.02f-047    2020-10-13 BWC  Add the HP test machine to the configuration
//
// 2.02e-046    2020-09-17 BWC  Rename to mwax_udp2sub for consistency.  Comment out some unused variables to stop compile warnings
//                              Change the cfitsio call for reading strings from ffgsky to ffgkls in hope it fixes the compile on BL server. (Spoiler: It does)
//
// 2.02d-045    2020-09-09 BWC  Switch back to long baseline configuration
//                              Make UDP_num_slots a config variable so different servers can have different values
//                              Do the coarse channel reversal above (chan>=129)
//                              Change MODE to NO_CAPTURE after the observation ends
//
// 2.02c-044    2020-09-08 BWC  Read Metafits directly from vulcan. No more metabin files
//
// 2.02b-043    2020-09-03 BWC  Write ASCII header onto subfiles.  Need to fake some details for now
//
// 2.02a-042    2020-09-03 BWC  Force switch to short baseline tile ids to match medconv
//                              Add heaps of debugs
//
// 2.01a-041    2020-09-02 BWC  Read metabin from directory specified in config
//
// 2.00a-040    2020-08-25 BWC  Change logic to write to .sub file so that udp packet payloads are not copied until after the data arrives for that sub
//                              Clear out a lot of historical code that isn't relevant for actual sub file generation (shifted to other utilities)
//
// 1.00a-039    2020-02-07 BWC  Tell OS not to buffer disk writes.  This should improve memory usage.
//
// 1.00a-038    2020-02-04 BWC  Add feature to support multiple coarse channels arriving from the one input (multicast *or* file) on recsim only
//                              Change recsim to make .sub files with only 1 rf_input.
//
// 1.00a-037    2020-02-03 BWC  Ensure .sub is padded to full size even if tiles are missing.  Improve reading udp packets from file
//
// 1.00a-036    2019-12-10 BWC  Add recsim as a Perth server
//                              Unnecessary functions for new MWA correlator removed
//
// 3.00a-009    2018-02-01 BWC  Added support for multiple EDT cards via -u command line option
//
// 3.00a-008    2017-01-12 BWC  Add a check for leap seconds during startup
//
// 3.00a-007    2017-01-12 BWC  Ignore EDT card data until time specified on command line (ie delay memory capture of data)
//                              Abort after writing max_files to disk
//                              Comment out debug lines to write .raw files (but leave in the memory copy to the temp buffers for now)
//                              Comment out edt_flush_fifo() since it appears to cause the other channels to glitch (Maybe it kills fifos on all channels?)
//
// 3.00a-006    2017-01-06 BWC  Add more debug statements to disk IO code and tweak timing of when semaphores are used
//
// 3.00a-005    2017-01-04 BWC  Add named semaphore as a mutual exclusion mechanism for disk IO
//
// 3.00a-004    2016-11-03 BWC  Add command line option -b for setting the number of EDT buffers and option -d for setting their size in MB
//
// 3.00a-003    2016-11-01 BWC  Add raw debug of EDT card packets to disk
//
// 3.00a-002    2016-08-04 BWC  Add option to suppress writing to disk unless -o used to set observation id
//                              Change default directory for disk files to .
//
// 3.00a-001    2016-07-13 BWC  Fork off vcsv2_021.c source to begin raw MWA receiver reading code.
//
//===================================================================================================================================================
//
// To Compile:  gcc edt2udp_###.c -lpthread -ledt -oedt2udp -Ofast -Wall -march=native                                          Newer OS
//              gcc edt2udp_###.c -lpthread -ledt -oedt2udp -O3 -march=native -DSYSV -L. -lrt -I/opt/EDTpcd -lm -std=c99        Older OS incl VCS boxes
//
//              There should be NO warnings or errors on compile!
//
// To run:      From Helios type:
//                      for i in {01..16};do echo vcs$i;ssh vcs$i 'numactl --cpunodebind=0 --membind=0 /vulcan/vcsv2/edt2udp_### > /dev/null &';done
//
//              From medconv01 type:
//                      numactl --cpunodebind=0 --membind=0 ./edt2udp -u 0 -c 0 > /dev/null &
//                      numactl --cpunodebind=0 --membind=0 ./edt2udp -u 0 -c 1 > /dev/null &
//                      numactl --cpunodebind=0 --membind=0 ./edt2udp -u 0 -c 2 > /dev/null &
//                      numactl --cpunodebind=1 --membind=1 ./edt2udp -u 1 -c 0 > /dev/null &
//                      numactl --cpunodebind=1 --membind=1 ./edt2udp -u 1 -c 1 > /dev/null &
//                      numactl --cpunodebind=1 --membind=1 ./edt2udp -u 1 -c 2 > /dev/null &
//
// To check if running, from Helios type:
//			for i in {01..16};do echo -n vcs$i'  ';ssh vcs$i 'ps x | grep edt[2]';done
//
// To stop:     for i in {01..16};do echo -n vcs$i'  ';ssh vcs$i 'pkill -2 edt2udp_###';done
//
// To do:       Monitor receiver health via 'synced', arrival time etc.  Maybe add 'Last_Buff_time' and estimated NTP of start of second to OneSecBuff struct
//              Clobber the last 1279998 time stamp with 1279999 as it's added to the flip buffer
//              Update character rate calculation from 34/9
//              Change file name to reflect receiver and fibre number
//              Re-enable CPU affinity
//              Make buffer size a command line parameter and play with values
//              Try to make 1279998/1279999 check better able to handle both corrected and uncorrected data
//              Play around with OS memory allocation (95% and never over-allocate)
//===================================================================================================================================================

#define _GNU_SOURCE
#define WORKINGCHAN 8

#include "edtinc.h"
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <signal.h>

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#include <unistd.h>
//#include <time.h>

//---------------- Define our old friends -------------------

//#define FALSE 0
//#define TRUE !(FALSE)

#define BOOL int
#define INT8 char
#define UINT8 unsigned char
#define INT16 short
#define UINT16 unsigned short
#define INT32 int
#define UINT32 unsigned int
#define INT64 long long int
#define UINT64 unsigned long long int

#define YIELD pthread_yield()
//#define YIELD usleep(1000)

//---------------- MWA external Structure definitions --------------------

#pragma pack(push,1)                          // We're sharing this structure with other programs, so we want/need to force the compiler not to add it's own idea of structure padding

typedef struct mwa_udp_packet {               // Structure format for the MWA data packets

    uint8_t packet_type;                      // Packet type (0x00 == Binary Header, 0x20 == 2K samples of RRI Voltage Data in complex 8 bit real + 8 bit imaginary format)
    uint8_t freq_channel;                     // The current coarse channel frequency number [0 to 255 inclusive].  This number is available from the header, but repeated here to simplify archiving and monitoring multiple frequencies.
    uint16_t rf_input;                        // maps to tile/antenna and polarisation (LSB is 0 for X, 1 for Y)
    uint32_t GPS_time;                        // [second] GPS time of packet (bottom 32 bits only)
    uint16_t subsec_time;                     // count from 0 to PACKETS_PER_SEC - 1 (from header)  Typically PACKETS_PER_SEC is 625 in MWA
    uint8_t spare1;                           // spare padding byte.  Reserved for future use.
    uint8_t edt2udp_id;                       // Which edt2udp instance generated this packet and therefore a lookup to who to ask for a retransmission (0 implies no retransmission possible)
    uint16_t edt2udp_token;                   // value to pass back to edt2udp instance to help identify source packet.  A token's value is constant for a given source rf_input and freq_channel for entire sub-observation
    uint8_t spare2[2];                        // Spare bytes for future use
    uint16_t volts[2048];                     // 2048 complex voltage samples.  Each one is 8 bits real, followed by 8 bits imaginary but we'll treat them as a single 16 bit 'bit pattern'

} mwa_udp_packet_t ;

//----------------

typedef struct medconv_health {			// Structure format for the health packets to send to M&C

    uint8_t message_type;			// Health packet format.  Currently only 0x01 for 'announcement of good 1 second data arrival'
    uint8_t medconv_state;			// Current state of medconv process.  0x01 for 'awaiting new RRI receiver data'

    uint32_t GPS_time;				// The GPS second assigned to the current 1 second data block.
    int32_t arrival_offset;			// The *estimated* time offset in nanoseconds between assigned GPS second roll-over and arrival of first packet.
                                                // NB: Signed value with possible -ve values!
    uint32_t last_GPS_time;			// The GPS second assigned to the last good 1 second data block seen (before the current one)

    uint8_t seen_unusable;			// How many 'unusable' blocks seen since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
    uint8_t seen_junk;				// How many 'junk' blocks seen since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
    uint8_t seen_badsync;			// How many times did the decoding thread indicate bad or no sync since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
    uint8_t seen_lostsync;			// How many times did we lose edt block sync since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
    uint8_t seen_other;				// How many other warnings occurred since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)

    uint8_t receiver;				// Decoded RRI receiver number from the current 1 sec of data.  Will be 1 to 16 inclusive (assuming message type supports this)
    uint8_t fibre3;				// Decoded RRI fibre number on that receiver.  Will be 0, 1 or 2 (assuming message type supports this)
    uint8_t lane;				// Decoded system wide fibre lane.  Will be 0 to 47 inclusive (assuming message type supports this)
    uint8_t edt_unit;				// EDT card unit number (0 or 1) for the two cards that are (or might be?) in a medconv server
    uint8_t edt_channel;			// EDT channel number (0, 1 or 2) for the 1st, 2nd or 3rd SFP socket (port) on the EDT card

    uint8_t instance;				// Unique medconv process instance for the system.  Will be 1 to 60 inclusive.
    char hostname[10];				// medconv hostname as a null terminated string.  eg: medconv03{null}.  Always in the form of 9 ASCII printable chars plus a null (0x00)
    int32_t pid;				// Process ID of this process on this server.
    uint16_t build;				// Software version number of the code generating this packet.

} medconv_health_t ;

#pragma pack(pop)                               // Set the structure packing back to 'normal' whatever that is

//----------------

typedef struct medconv_config {               // Structure for configuration of each medconv instance

    uint8_t edt2udp_id;                       // Which edt2udp instance generated this packet and therefore a lookup to who to ask for a retransmission (0 implies no retransmission possible)
    char host[21];
    int edt_unit;
    int edt_channel;
    char local_if[20];
    char local_mc_if[20];

} medconv_config_t ;

//---------------- internal structure definitions --------------------

typedef struct OneSecBuff {

    INT64 Buff_time;                            // GPS time of this buffer
    UINT32 GPS_32;                              // Bottom 32 bits of GPS time. Used in network packets where upper 32 bits can be assumed.
    INT64 obs_id;                               // Place to store the obs_id.  Assumed to be the GPS time of the start of the observation

    struct timespec sec_start_time;		// Time that the first packet for this second is handed to the application (us) in linux format
    int sec_start2end;				// The number of bytes after the start of the second and before we got a chance to record the time stamp above.

    INT16 fibre_lane;                           // 0-47, includes both receiver number and which of the three fibres we're connected to
    int rec;                                    // The receiver number that this one second block came from. 1 based so 1 to 16 inclusive.
    int fibre3;                                 // as above.  Was this block from fibre 0, 1 or 2 on this receiver. Fibre numbers are 0 based.

    uint16_t rf_input[16];                      // the destination rf_input name ordered by position in the RRI packets for this second
    uint8_t sky_freq[8];                        // the sky frequency of each of the eight channels in this second ordered by position in the RRI packet
    int multicast_dest[8];                      // what to set the destination multicast address and port to, in the order that coarse channels are listed in the RRI packet. 1 to 24 inclusive.

    int Buff_prev;                              // Index of buffer holding the most recent second before this second.  May not be contiguous! -1 for none.
    int Buff_next;                              // Index of buffer holding the next second after this second.  May not be contiguous! -1 for none.

    int Converted2udp;                          // Has this buffer been converted into 80000 udp packets in 8+8i format.
    BOOL Sent2nic;                              // Has this buffer been converted into 80000 udp packets in 8+8i format *and then* sent out to the NIC?

    UINT64 Buff_locks;                          // Bitmap of threads currently holding read locks on this buffer.  If a read lock exists, the buffer cannot be reused.
    UINT64 Neededby;                            // Bitmap of threads that are going to want to process this block.  Bits are reset to 0 by the relevant threads when they're no longer needed.

    UINT8  udp_ndx;                             // which of the udp indexes is the right one for this buffer?  (0 to 15 inclusive assuming UDP_BUFS is 16)

    UINT8 *Buff_ptr;                            // Pointer to the ~205MB buffer for this second.

} OneSecBuff_t;

//----------------

typedef struct FlipBuff {

    int OneSecBuff_ndx;                         // Index into OneSecBuff array that this flip buffer equates to.
    INT64 Buff_time;                            // GPS time of this buffer

    struct timespec sec_start_time;		// Time that the first packet is handed to the application (us) in linux format
    int sec_start2end;				// The number of bytes after the start of the second and before we got a chance to record the time stamp above.

    INT16 fibre_lane;                           // 0-47, includes both receiver number and which of the three fibres we're connected to
    UINT8 *Buff_ptr;                            // Pointer to the ~205MB buffer for this second.
    pthread_mutex_t Buff_mx;                    // The mutex object associated with this object.

} FlipBuff_t;

//----------------

typedef struct metabin {
    int64_t obs_id;
    int64_t last_GPS;
    int obs_mode;
    uint16_t rf_input_map[16][16];              // From the metabin, a list of rf_input "tile_id"s sorted by receiver number followed by the order in which they appear in that receivers RRI packets
    uint8_t sky_freq_map[3][8];                 // From the metabin, a list of sky frequencies [0 to 255 inclusive] sorted by which of the three fibres from a receiver they are on followed by the order in RRI packets
    int multicast_dest_map[3][8];               // From the metabin, the complete list of all multicast streams (24) but sorted by which of the three fibres from a receiver they are on followed by the order in RRI packets
} metabin_t;

//---------------------------------------------------------------------------------------------------------------------------------------------------
// These variables and #defines are shared by all threads.  "file scope"
// Some are only accessable via a Mutex lock.  Some are basically #defines in the form of variables.  Others are volatile.
//---------------------------------------------------------------------------------------------------------------------------------------------------

#define SUBSECSPERSEC (625)
#define CHANPERPACKET (8)
#define CHANPERSYSTEM (24)
#define INPPERPACKET (16)
#define SAMPLES_PER_PACKET (2048)
#define UDP_PER_MC (80000)
#define UDP_BUFS (16)
// UDP_BUFS must be a power of 2.  Eight isn't enough, 32 is probably too gready on RAM.  I guess that leaves 16.

#define MAX_UDP_PER_CALL (128)
#define MAX_OBS_IDS (8)

volatile BOOL terminate = FALSE;                        // Global request for everyone to close down
volatile BOOL kick_edt = FALSE;		                   		// Global request (probably from a sigusr1 signal sent to us) that we should reset all the EDT card ring buffers

volatile INT64 OneSecBuff_Sec = 0;                      // GPS_Time of the latest block completely handed off to 'buff2udp' worker thread
volatile INT64 OneSecBuff_udp = 0;                      // GPS_Time of the latest block completely handed off to 'udp2nic' worker thread
volatile BOOL checkifwriteneeded = FALSE;               // We need to check if there is an early buffer that needs to be written to disk.  False positive allowed.
volatile INT64 udp_upto = 10000;                        // GPS time of the last second we have looked at.  Unless checkifwriteneeded is true, only times after this are worth looking at.
volatile INT64 rri2udp = 0;                             // The total number of *equivalent* udp packets created by buff2udp TIMES 16. Not the number *actually* finished. eg Half way through 128 udps will count as 64*16 (1024).

// volatile int latest_num_gulps = 80;                  // The number of gulps each coarse_buff_size will be divided up into for socket writing.  MUST DIVIDE EVENLY INTO 2000.  See table later in source code.

static const int OneSecBuff_max = 215;                  // Total number of allowed buffers for THIS process.  At 95% overcommit_ratio a total of 463 (shared) buffers were malloced before failure. (483 @ 99%)
int OneSecBuff_inuse = 0;                               // Number of buffers allocated and managed
int OneSecBuff_first = -1;                              // Index into metadata array for earliest chronological block
int OneSecBuff_last = -1;                               // Index into metadata array for most recent chronological block

FlipBuff_t FlipBuffArray[2];                            // Metadata about the two one second buffers we're currently using for the the write from the EDT card (1 live, 1 ready to go at short notice)
OneSecBuff_t OneSecBuffArray[220];                      // This is the array of control metadata for the buffers, not the buffers themselves, so this isn't very much RAM
pthread_mutex_t buff_array_mx;                          // Controls access to the metadata for the OneSecBuffArray
metabin_t obs_meta[MAX_OBS_IDS];                        // Room for the metadata for the last few observations (NB not subobservations, but actual full observations)

mwa_udp_packet_t *udpbuff[UDP_BUFS];                    // udpbuff is an array of pointers to blocks of 80000 udp packets.

static const int packets_per_sec = 1280000;             // ...and they're numbered from 0 to 1279999 inclusive except due to a bug the last quotes a duplicate number 1279998
static const int OneSecBuff_Size = 1280000 * 168;       // How big is each second worth of main data (excluding metadata)
//static const int NumChan=8;                           // Total number of coarse channels we need to handle.  8 on a singe fibre (3 fibres per receiver each handled by different processes)
//static const int time_points_per_sec = 20;            // The protocol specifies 20 groups (of 500 packets of 10kHz) per second
//static const int coarse_buff_size = 528000;           // Protocol specifies 528000 bytes (2000 packets) for each coarse chan before moving on to next. Equal to OneSecBuff_Size / NumChan / time_points_per_sec
//static const int fiftyms_buff_size = 12672000;        // Protocol specifies 12672000 bytes (24 x 2000 packets) for each 50ms time step before moving on to next.  Equal to coarse_buff_size * NumChan

int GPS_offset = 315964782;                             // The number of seconds that must be SUBTRACTED from the Linux Epoch to get MWA's GPS time.  Corrected for leap seconds in startup code

int edt_unit=0;                                         // Default to first EDT card
int edt_channel=2;                                      // EDT card input channel.  Default to the channel that vcs boxes have a direct fibe plugged in to (2)
INT64 current_obs_id=1000000000;                        // WIP!!! The current obs id read from the command line.
BOOL verbose = FALSE;                                   // Default to minimal debug messages
char *my_path = ".";                                    // Pointer to my path

INT64 start_capture_time = 0;                           // Unless overridden on the command line, start capture at GPS time = 0 (ie asap)
int max_files=2147483647;                               // Let's set a 'silly large' maximum number of files that isn't really a limit at all

int edtbufs = 12;                                       // Set a default number of buffers for the EDT card
int edtbufsize = 12;                                    // Set a default size in MegaBytes for the EDT card buffers.  NB: If this number is greater than 23, then the maths for arrival times needs tweaking.

static const int too_late_ns = 50000000;            		// If a seconds data arrives after this arrival lag twice, assume the edt card needs a kick

medconv_config_t conf;                                  // A place to store the configuration data for this instance of the program.  ie of the 60 copies running on 10 computers or whatever
medconv_health_t health;	                           		// Health data shared among threads.  Transmitted by flip2buff to multicast
cpu_set_t physical_id_0, physical_id_1;                 // Make a CPU affinity set for socket 0 and one for socket 1 (NUMA node0 and node1)

const UINT16 port_layout[] = {6, 4, 2, 0, 14, 12, 10, 8}; // Map logical to physical tile assignments.

UINT64 counters[100];

volatile INT64 monitor_udp_count = 0;     // Total number of UDP packets sent.
volatile INT64 monitor_udp_last = 0;      // Number of UDP packets sent as of the most recent activity status check.
struct timespec monitor_udp_time;   // Time of the most recent activity status check.


//---------------------------------------------------------------------------------------------------------------------------------------------------
// unpackhdr - Unpack the receiver packet header into components
// Is passed a pointer to the beginning of a packet and returns that packet's sequence number in the second of data
// Returns a number from 0 to 1,279,999 inclusive or a negative number if the header is not formatted correctly.
// If passed a fibre_lane then confirm that this header is for the same lane.  If passed a lane of -1 then fill the parameter with the current header's value.
//---------------------------------------------------------------------------------------------------------------------------------------------------

INT32 unpackhdr(UINT16 *ptr, INT16 *fibre_lane)
{
    if (*ptr++ != 0x0800) return(-1);                                           // If it doesn't start with 0x800 then it's not a valid header

    UINT16 hdr_word = *ptr++;                                                   // Get the next word. Should look like: 000r rrrr ff0s ssss

    INT32 receiver = (hdr_word >> 8) & 0x1f;                                    // 5 bits 1-16
    INT32 fibre = (hdr_word >> 6) & 0x3;                                        // 2 bits 0-2 for now.  Later will have (receiver-1)*3 added to it to give a system wide fibre number
    INT32 packet_num = (hdr_word & 0x1f) << 16;                                 // 5 bits (Top five bits of packet sequence number)

    if ( receiver>16 || receiver <1 ) return(-2);                               // Invalid receiver number.  Must be 1 to 16 inclusive
    if ( fibre == 3 ) return(-3);                                               // fibre can be 0,1 or 2 here.  Encoded in 2 bits, 3 is the only invalid pattern
    if ( (hdr_word & 0b1110000000100000) != 0) return(-4) ;                     // Unused bits are set

    hdr_word = *ptr;                                                            // Get last header word. Should look like: ssss ssss ssss ssss

    packet_num |= hdr_word;                                                     // Populate the bottom 16 bits of the packet number

    if (packet_num > 1279999) return(-5);                                       // Results are unbelievable.  This header is bad.

    fibre += (receiver-1) * 3;                                                  // Which of the 48 receiver rocketIO lanes *in the system* is this packet?

    if (*fibre_lane == -1) *fibre_lane = fibre;                                 // We've never recorded which fibre_lane we're committed to, so any will do

    if (*fibre_lane != fibre) return(-6);                                       // This isn't the lane we're committed to.  Flag the count as bad to force a resync
                                                                                // Probably a buffer out of sync rather than a fibre cable swap, but it's bad either way.

    if (packet_num == 1279998) {                                                // Packets flagged as 1279998 *could* be really number 1279999 due to bug in receiver firmware
      if (*(ptr+84) != 0x87fe) packet_num++;                                    // If the least significant 16 bits of the next packet's sequence number looks like it's for another 1279998
    }                                                                           // then we believe this one, otherwise *we* should do the increment that the receiver *should* have done

    return(packet_num);
}

//---------------------------------------------------------------------------------------------------------------------------------------------------
// inc_clip - Increment an unsigned char but clip to 255 (ie prevent rollover)
//---------------------------------------------------------------------------------------------------------------------------------------------------

void inc_clip ( uint8_t *var_to_inc )
{
    if ( *var_to_inc < 255) (*var_to_inc)++;					// Iff it's currently less than 255, then add one more to it.
}

//---------------------------------------------------------------------------------------------------------------------------------------------------
// read_config - use our hostname and edt parameters to find ourselves in the list of possible configurations
// Populate a single structure with the relevant information and return it
//---------------------------------------------------------------------------------------------------------------------------------------------------

void read_config ( char *us, int edtu, int edtc, medconv_config_t *config )
{

#define MAXINSTANCE (97)

    int instance_ndx = 0;                                                                       // Start out assuming we don't appear in the list

    medconv_config_t mc_config[MAXINSTANCE] = {
       { 0,"unknown",0,0,""}
      ,{ 1,"medconv11",0,0,"192.168.90.1","10.128.6.11"}
      ,{ 2,"medconv11",0,1,"192.168.90.1","10.128.6.11"}
      ,{ 3,"medconv11",0,2,"192.168.90.1","10.128.6.11"}
      ,{ 4,"medconv11",1,0,"192.168.90.2","10.128.6.11"}
      ,{ 5,"medconv11",1,1,"192.168.90.2","10.128.6.11"}
      ,{ 6,"medconv11",1,2,"127.0.0.1","10.128.6.11"}

      ,{ 7,"medconv12",0,0,"192.168.90.3","10.128.6.12"}
      ,{ 8,"medconv12",0,1,"192.168.90.3","10.128.6.12"}
      ,{ 9,"medconv12",0,2,"192.168.90.3","10.128.6.12"}
      ,{10,"medconv12",1,0,"192.168.90.4","10.128.6.12"}
      ,{11,"medconv12",1,1,"192.168.90.4","10.128.6.12"}
      ,{12,"medconv12",1,2,"192.168.90.4","10.128.6.12"}

      ,{13,"medconv13",0,0,"192.168.90.5","10.128.6.13"}
      ,{14,"medconv13",0,1,"192.168.90.5","10.128.6.13"}
      ,{15,"medconv13",0,2,"192.168.90.5","10.128.6.13"}
      ,{16,"medconv13",1,0,"192.168.90.6","10.128.6.13"}
      ,{17,"medconv13",1,1,"192.168.90.6","10.128.6.13"}
      ,{18,"medconv13",1,2,"192.168.90.6","10.128.6.13"}

      ,{19,"medconv14",0,0,"192.168.90.7","10.128.6.14"}
      ,{20,"medconv14",0,1,"192.168.90.7","10.128.6.14"}
      ,{21,"medconv14",0,2,"192.168.90.7","10.128.6.14"}
      ,{22,"medconv14",1,0,"192.168.90.8","10.128.6.14"}
      ,{23,"medconv14",1,1,"192.168.90.8","10.128.6.14"}
      ,{24,"medconv14",1,2,"192.168.90.8","10.128.6.14"}

      ,{25,"medconv15",0,0,"192.168.90.9","10.128.6.15"}
      ,{26,"medconv15",0,1,"192.168.90.9","10.128.6.15"}
      ,{27,"medconv15",0,2,"192.168.90.9","10.128.6.15"}
      ,{28,"medconv15",1,0,"192.168.90.10","10.128.6.15"}
      ,{29,"medconv15",1,1,"192.168.90.10","10.128.6.15"}
      ,{30,"medconv15",1,2,"192.168.90.10","10.128.6.15"}

      ,{31,"medconv16",0,0,"192.168.90.11","10.128.6.16"}
      ,{32,"medconv16",0,1,"192.168.90.11","10.128.6.16"}
      ,{33,"medconv16",0,2,"192.168.90.11","10.128.6.16"}
      ,{34,"medconv16",1,0,"192.168.90.12","10.128.6.16"}
      ,{35,"medconv16",1,1,"192.168.90.12","10.128.6.16"}
      ,{36,"medconv16",1,2,"192.168.90.12","10.128.6.16"}

      ,{37,"medconv17",0,0,"192.168.90.13","10.128.6.17"}
      ,{38,"medconv17",0,1,"192.168.90.13","10.128.6.17"}
      ,{39,"medconv17",0,2,"192.168.90.13","10.128.6.17"}
      ,{40,"medconv17",1,0,"192.168.90.14","10.128.6.17"}
      ,{41,"medconv17",1,1,"192.168.90.14","10.128.6.17"}
      ,{42,"medconv17",1,2,"192.168.90.14","10.128.6.17"}

      ,{43,"medconv18",0,0,"192.168.90.15","10.128.6.18"}
      ,{44,"medconv18",0,1,"192.168.90.15","10.128.6.18"}
      ,{45,"medconv18",0,2,"192.168.90.15","10.128.6.18"}
      ,{46,"medconv18",1,0,"192.168.90.16","10.128.6.18"}
      ,{47,"medconv18",1,1,"192.168.90.16","10.128.6.18"}
      ,{48,"medconv18",1,2,"192.168.90.16","10.128.6.18"}

      ,{49,"medconv19",0,0,"192.168.90.17","10.128.6.19"}
      ,{50,"medconv19",0,1,"192.168.90.17","10.128.6.19"}
      ,{51,"medconv19",0,2,"192.168.90.17","10.128.6.19"}
      ,{52,"medconv19",1,0,"192.168.90.18","10.128.6.19"}
      ,{53,"medconv19",1,1,"192.168.90.18","10.128.6.19"}
      ,{54,"medconv19",1,2,"192.168.90.18","10.128.6.19"}

      ,{55,"medconv20",0,0,"192.168.90.19","10.128.6.20"}
      ,{56,"medconv20",0,1,"192.168.90.19","10.128.6.20"}
      ,{57,"medconv20",0,2,"192.168.90.19","10.128.6.20"}
      ,{58,"medconv20",1,0,"192.168.90.20","10.128.6.20"}
      ,{59,"medconv20",1,1,"192.168.90.20","10.128.6.20"}
      ,{60,"medconv20",1,2,"192.168.90.20","10.128.6.20"}





    };

    for ( int loop = 0 ; loop < MAXINSTANCE ; loop++ ) {        // Check through all possible configurations

      if (( mc_config[loop].edt_unit == edtu ) & ( mc_config[loop].edt_channel == edtc ) & ( strcmp( mc_config[loop].host, us ) == 0 ) ) {
        instance_ndx = loop;                                    // if the edt card config matches the command line and the hostname matches
        break;                                                  // We don't need to keep looking
      }

    }
    *config = mc_config[ instance_ndx ];                        // Copy the relevant line into the structure we were passed a pointer to
}

//===================================================================================================================================================
// THREAD BLOCK.  The following functions are complete threads
//===================================================================================================================================================

//---------------------------------------------------------------------------------------------------------------------------------------------------
// edt2flip - EDT Card IO Thread.
// High priority thread for pulling data off a single EDT channel, accumulating it into 1 second chucks
// and passing to another thread via two flip buffers to be insert into the main coarse channel buffers.
//---------------------------------------------------------------------------------------------------------------------------------------------------

void *edt2flip()
{
    printf("edt2flip started\n");
    fflush(stdout);

//---------------- Initialize and declare variables ------------------------

    EdtDev *edt_p;

    INT64 Current_GPStime = 0;                                          // The GPS time of the one second block we're currently assembling
//    INT32 Current_GPStime_nsec;                                         // nsecs after GPStime we estimate packet 0 hit the input to the EDT card.  Adjusted by its location in buffer

//    INT64 GPStime_of_fail = -1;                                         // -1 means never failed (since start of process)
//    int failures_this_sec = 0;                                          // We'll be watching this to decide if the EDT card has lost DMA buffer consistency like after an fPBF 1st fibre reset
//    int failures_allowed = 10;                                          // How many buffer failures in a second before we attempt an EDT card buffer reset?

    int bufsize = edtbufsize*1024*1024;                                 // Size for EDT cards DMA buffer.  Comes out of bottom 4GB.  Allocated by EDT drivers.

/*
    int raw_bufs_to_dump = 99;                                          // For debugging, we will keep this many raw EDT buffers to look at after closedown
    int raw_buf_for_dump = 0;                                           // The index number of the next one to write to
    UINT8 *raw_bufs;
    if ( posix_memalign((void **)&raw_bufs,4096,raw_bufs_to_dump*bufsize) != 0 ) raw_bufs = NULL;
    char my_debug_file[300];                                          // Room for the name of the debug files we're creating
    int debugfiledesc;                                                        // The file descriptor we'll use for our debug file writes
*/

    int packet_size_8 = 168;                                            // A receiver packet is 168 x 8bit bytes long.
    int packet_size_16 = packet_size_8 / 2;                             // A receiver packet is 84 x 16bit words long.
    int packets_per_buff = bufsize / packet_size_8;                     // bytes divided by bytes
    int packet_remainder = (bufsize / 2) - (packets_per_buff * packet_size_16) ;        // All in words, not bytes. How many 16 bit words in the remainder?
    int big_step_in = (packets_per_buff-3) * packet_size_16;            // If we find a packet at the start of the buffer, how far can we jump to a valid packet header near the end?
                                                                        // the packet at the start could be some way in and we need room at the end for the full 3 word header plus a possible check of one packet later for packet 1279998

//    printf("Big step in %d, packets per buff %d\n", big_step_in, packets_per_buff);

    int numbufs = edtbufs;                                              // EDT recommend 4.

    UINT8 *dma_buf_8;
    UINT16 *dma_buf_16;                                                 // EDT thinks it returns a pointer to bytes, but we want to treat it all as 16 bit words.

    INT16 fibre_lane = -1;                                              // Which receiver fibre RocketIO lane.  From 0 to 47 inclusive.  Includes receiver number as well as fibre on receiver.  -1 == unknown
    BOOL synced = FALSE;                                                // Assume we're NOT synced up with respect to 1 second arriving packets for now
    struct timespec arrive_time;					// Last buffer arrival time

    struct timespec sec_start_time;					// Time that the first buffer for this second is handed to the application
    int sec_start2end;							// The number of bytes after the start of the second and before we got a chance to record the time stamp above.

    int loop, next_packet_ndx = 0;                                      // Initialise to keep -Wall warnings happy.
    int this_packet_no, next_packet_no = 0;
    int offset_to_nxt_sec;

    int last_good_packet_no;						// When saving a glitched buffer, what was the last good header before the glitch?
    UINT16 *last_good_packet_ptr;					// where was it?
    int last_packet_to_check;						// which was the packet near the end that we discovered was bad?
    int check_packet_no;						// What packet after the glitch seemed to have a good header again?
    UINT16 *check_packet_ptr;						// where was it?

    int written_to_flip = 0;                                            // Number of bytes already written to the flip buffer
    UINT8 *write_flip;
    int wflip = 0;                                                      // Start from flip buffer 0.  Every loop, we'll swap between 0 and 1.

    int flip_buffers_so_far = 0;                                        // Remember how many buffers we've added

//---------------- Set up inital state of flip buffer  ------------------------

      pthread_mutex_lock( &FlipBuffArray[wflip].Buff_mx );              // Get an inital lock on the mutex to set things up
      write_flip = FlipBuffArray[wflip].Buff_ptr;                       // Get the memory address pointer for the very first one second block.

//---------------- Set up EDT card ------------------------

    if ((edt_p = edt_open_channel(EDT_INTERFACE, edt_unit, edt_channel)) == NULL) {     // Is the EDT card installed and alive?
      printf("edt_open_channel failed\n");
      fflush(stdout);
      terminate = TRUE;                                                         // This is fatal.  Tell everyone to pack up and go home.
      pthread_exit(NULL);
    }

    if (edt_configure_ring_buffers(edt_p, bufsize, numbufs, EDT_READ, NULL) == -1) {
      printf("Unable to configure %d ring-buffers of %d bytes\n", numbufs, bufsize);
      fflush(stdout);
      terminate = TRUE;                                                 // This is fatal.  Tell everyone to pack up and go home.
      pthread_exit(NULL);
    }

    edt_set_rtimeout(edt_p,1000);                                       // Set card to time out all reads after 1 second

//    edt_flush_fifo(edt_p) ;                                           // Flush the input fifo.  We only want new stuff!

    edt_start_buffers(edt_p, numbufs) ;                                 // start the transfers and allow only numbufs before stopping

//---------------- Main EDT reading loop ------------------------

    while(!terminate) {

      if ( kick_edt ) {									// Are we supposed to reset all the EDT ring buffers?  'cos if we are...
        edt_disable_ring_buffers(edt_p);						// get back the valuable low memory (<4GB)

        edt_close(edt_p) ;								// Completely hand back the edt card port

        if ((edt_p = edt_open_channel(EDT_INTERFACE, edt_unit, edt_channel)) == NULL) {	// Now grab it again, but if it fails
          printf("edt_open_channel failed\n");
          fflush(stdout);
          terminate = TRUE;								// we made things worse and we should terminate
          pthread_exit(NULL);
        }

        if (edt_configure_ring_buffers(edt_p, bufsize, numbufs, EDT_READ, NULL) == -1) {	// recreate the buffers, but if that failed
          printf("Unable to configure %d ring-buffers of %d bytes\n", numbufs, bufsize);
          fflush(stdout);
          terminate = TRUE;								// we made things worse and we should terminate
          pthread_exit(NULL);
        }

        edt_set_rtimeout(edt_p,1000);							// Set card to time out all reads after 1 second.  Probably not needed, but can't hurt right?
        edt_flush_fifo(edt_p) ;                                                   	// Flush the input fifo.  We only want new stuff!
        edt_start_buffers(edt_p, numbufs) ;                                       	// restart the transfers and allow only numbufs before stopping
        kick_edt = FALSE;

        printf("EDT Card ring buffer reset performed\n");				// Write it to the log
        fflush(stdout);
      }

      dma_buf_8 = edt_wait_for_buffers(edt_p, 1);                                       // Get the data from the card OR if it was a timeout get a buffer of useless junk.
      clock_gettime( CLOCK_REALTIME, &arrive_time);					// Grab the time now for accuracy.  We may want it later.

      edt_start_buffers(edt_p, 1);                                                      // Tell the card we can handle one more buffer now that we swallowed one.

      dma_buf_16 = (UINT16 *) dma_buf_8;                                                // We want the address as both a pointer to a byte and a short for ease of addressing

//      printf(".");
//      fflush(stdout);

//      memcpy( raw_bufs+(raw_buf_for_dump*bufsize), dma_buf_8, bufsize );                // Copy the whole EDT buffer into the debugging array
//      if ( ++raw_buf_for_dump == raw_bufs_to_dump ) raw_buf_for_dump = 0;               // Cycle througn to the next buffer

      if (synced) {                                                                     // Even if we *think* we're synced up, we should check that the data is believable before committing to it.

        if ((next_packet_no != unpackhdr(&dma_buf_16[next_packet_ndx], &fibre_lane)) || // Is the start of this buffer unbelievable, including the receiver and fibre numbers?   ...or...
            ((next_packet_no+packets_per_buff-3)%packets_per_sec != unpackhdr(&dma_buf_16[next_packet_ndx+big_step_in], &fibre_lane))) {        // is a packet right near the *end* unbelievable

          synced = FALSE;                                                               // if so, then we have lost sync and need to abort this one second buffer assembly and resync everything.

//---------- we have lost sync. Let's try to find out what's the matter with the block even if it takes some time ----------

          if (next_packet_no == unpackhdr(&dma_buf_16[next_packet_ndx], &fibre_lane) ) {	// If the beginning of the buffer is good then it's probably some lost data in the buffer (rather than complete junk)

            // lets look through each packet from here to check its header looks okay.  When we get to one that *isn't* okay we'll assume we can trust all the packets up to (but not including) the last good header.
            // then we'll look for nice looking packet headers starting from immediately after the last good header before the glitch.  We'll need to check (just under) two whole packet lengths though if we looking for
            // a single burst of lost bytes.  That's because the burst could have lost (for example) just the header of an RRI packet.  Then there'd be two payloads from the last good header until the start of the usable
            // post glitch data.
            // Once all this is done we may be able to recover both the data before the glitch and after, exclusive of any whole packets that were damaged
            // (less some complications around broken headers hurting the preceding packet)

            last_good_packet_no = next_packet_no;					// We wouldn't be here if this packet wasn't good, so it's the earliest good one we know
            last_good_packet_ptr = &dma_buf_16[next_packet_ndx];			// and this is where we already worked out it was

            last_packet_to_check = (next_packet_no+packets_per_buff-3)%packets_per_sec;	// and things have gone bad by this packet, or (again) we wouldn't be here.

            check_packet_no = (last_good_packet_no + 1) % packets_per_sec;		// Let's start further testing from here.  NB It may have rolled over the count back to zero (ie next seconds data)
            check_packet_ptr = last_good_packet_ptr + packet_size_16;			// Set pointer to the next packet. NB the pointer isn't a pointer to a packet structure. It's a pointer to a UINT16.

            while ( check_packet_no != last_packet_to_check ) {				// We know that last packet is bad because its failure is how we got here (see outer 'if' statement)

              if ( check_packet_no != unpackhdr( check_packet_ptr, &fibre_lane ) ) break;	// Does packet number 'check_packet_no' have a good header? NB: Even if it does, its payload could still be toast

              last_good_packet_no = check_packet_no;					// This is now the last one we know is good
              last_good_packet_ptr = check_packet_ptr;					// and this is where we already worked out it was

              check_packet_ptr += packet_size_16;					// Increment pointer to the next packet. NB the pointer isn't a pointer to a packet structure. It's a pointer to a UINT16.
              check_packet_no = (check_packet_no + 1) % packets_per_sec;		// increment the packet number. Check for roll-over and get set for the next test.

            }

            // We now know that everything is fine in the buffer, right up to the beginning of the header for packet number 'last_good_packet_no'.  That packet itself can't be trusted though
            // Now lets see if it goes good again after that.

            check_packet_ptr = last_good_packet_ptr + 3;				// Start looking at the first byte after the last good header (Headers are 6 bytes, ie 3 * sizeof(UINT16) in length)

            for ( loop=0; loop < (packet_size_16+packet_size_16); loop++ ) {		// Look for twice the length of a packet for reasons explained above

              check_packet_no = unpackhdr( check_packet_ptr, &fibre_lane);		// Have a try to see if this looks valid. NB: It needs to be the same fibre lane as before!

              if ( check_packet_no >= 0 ) {						// Wow. It looks valid.  Maybe we're back in Kansas and can use the data from here. We need more checking to know for sure.
                // If we are fully synchronized and there was only one burst of lost characters, then we will be able to step through each one to the end of the buffer

                printf("\nPossible recovery npn=%d, np_ndx=%d, lgpn=%d, lgp_ndx=%ld, cpn=%d, cp_ndx=%ld, dist=%ld, lost=%ld, zero=%d",	//
                  next_packet_no,														//
                  next_packet_ndx,														//
                  last_good_packet_no,														//
                  ( last_good_packet_ptr - dma_buf_16 ),											//
                  check_packet_no,														//
                  ( check_packet_ptr - dma_buf_16 ),												//
                  ( check_packet_ptr - last_good_packet_ptr ),											//
                  ( check_packet_no - last_good_packet_no ) * packet_size_8 - ( 2 * ( check_packet_ptr - last_good_packet_ptr ) ),		//
                  ( check_packet_no - last_good_packet_no )											//
                  );

                break;
              }

              check_packet_ptr++;							// Move on a couple of bytes.  NB: The EDT card data is always aligned on 16bit (not byte) boundaries
            }

          }

          printf("\nlost sync:  ");
          printf( "%d, %d, %d; ",next_packet_no, unpackhdr(&dma_buf_16[next_packet_ndx], &fibre_lane),fibre_lane );
          printf( "%d, %d", (next_packet_no+packets_per_buff-3)%packets_per_sec, unpackhdr(&dma_buf_16[next_packet_ndx+big_step_in], &fibre_lane) );
//          printf( ", %d",raw_buf_for_dump );
          printf( "\n" );
          fflush(stdout);

          inc_clip( &health.seen_lostsync );						// Increment the number of times we've lost sync

        } else {                                                                        // Looks good.  Let's trust it.

          next_packet_no = next_packet_no + packets_per_buff + 1;                       // Prepare information to test the *next* buffer.  What packet will it start with? Careful. It may need tweaking.
          next_packet_ndx = next_packet_ndx + packet_size_16 - packet_remainder;        // Where in the buffer will it start? Careful. It may need tweaking.
          if (next_packet_ndx >= packet_size_16) {                                      // We stepped into the buffer too far.
            next_packet_no--;                                                           // We should only need to back off one packet.
            next_packet_ndx -= packet_size_16;
          }
          next_packet_no %= packets_per_sec;                                            // Check for a one second packet number rollover for the next buffer.

          // We now have a good buffer full of data to deal with.  It may contain the completion of a second and it may not.

          if (written_to_flip + bufsize < OneSecBuff_Size) {                            // If *no* completion of second
            memcpy( write_flip+written_to_flip, dma_buf_8, bufsize );                   // Copy the whole DMA buffer into the One Sec Write Buffer.  ~12MB of it.
            written_to_flip += bufsize;                                                 // and update how much we've written.
          } else {                                                                      // otherwise we *have* the end of a second
            memcpy( write_flip+written_to_flip, dma_buf_8, OneSecBuff_Size - written_to_flip );         // Copy just the remaining data for this second

            FlipBuffArray[wflip].Buff_time = Current_GPStime;                           // Save the time stamp of this second in the flip buffer so it can be later copied to the main array
            FlipBuffArray[wflip].fibre_lane = fibre_lane;                               // Save the lane. Later on, other threads will check if this has been changed and act appropriately

            FlipBuffArray[wflip].sec_start_time = sec_start_time;			// Time that the first buffer for this second was handed to the application (now a second ago)
            FlipBuffArray[wflip].sec_start2end = sec_start2end;				// The number of bytes after the start of the second and before we got a chance to record the time stamp above.

            // We have now completely filled the current write flip buffer and we're ready to give it away to another thread to insert into the working linked list.

            if ( Current_GPStime >= start_capture_time ) {                              // Have we reached the time when we wanted to start capturing data?

              if ( pthread_mutex_trylock( &FlipBuffArray[wflip^0x01].Buff_mx ) == 0 ) { // Try to get control of the OTHER one sec buffer, the one we're about to write to.  Do it BEFORE we let go of this one.
                pthread_mutex_unlock( &FlipBuffArray[wflip].Buff_mx );                  // Release control of this full one sec buffer.
                wflip ^= 0x01;                                                          // Flip the buffer!  If it *was* pointing to element zero, it's now pointing to element one and vice versa.

                if ( flip_buffers_so_far++ == max_files ) terminate = TRUE;             // Stop capturing data and prepare to abort if we've created buffers for the maximum number of files
                                                                                        // This will actually prepare one extra second, but flip2buff() won't add the last one if terminate is true

              } else {                                                                  // If we fail to get a mutex, we'll just lose this second's data and reuse the buffer we already have.
                printf( "s" );
                fflush( stdout );
                inc_clip( &health.seen_other );						// Increment the number of times bad stuff happens

              }

            } else {                                                                    // It isn't time to start saving data yet, so just ignore this second
              printf( "i\n" );
              fflush( stdout );
            }

            write_flip = FlipBuffArray[wflip].Buff_ptr;                                 // Get the memory address pointer for the new one second block.

            memcpy( write_flip, dma_buf_8+OneSecBuff_Size-written_to_flip, bufsize-(OneSecBuff_Size-written_to_flip) );         // Copy the start of the new second into the new write buffer
            written_to_flip = bufsize-(OneSecBuff_Size-written_to_flip);                                                        // Set the new tally for the new second's write buffer

            sec_start_time = arrive_time;						// The time we saw the last buffer from the EDT is now the start time for this new second
            sec_start2end = written_to_flip;						// and this is how many bytes of the new second were in that buffer (used for estimating the rollover time)

            Current_GPStime++;								// We stayed in sync for the whole sec, so assume we can just increment

          }

        }
      }

      if (!synced) {                                                                    // We don't know where in the data stream we are.  Try to work it out by looking for valid receiver headers

        for (loop=0; loop<packet_size_16; loop++) {                                     // Look at the first full packet size worth of data from the EDT to try to find a believable packet header

          fibre_lane = -1;                                                              // We'll take ANY receiver and fibre lane for now.  Later we'll insist that it remains the same as others in the buffer.

          this_packet_no = unpackhdr(&dma_buf_16[loop], &fibre_lane);                   // Have a try to see if this looks valid.  Populate fibre_lane to force later tests to confirm they're the same.
          if (this_packet_no<0) continue;                                               // This doesn't look like a valid packet header.  Try again in the next position.

          next_packet_no = unpackhdr(&dma_buf_16[loop+packet_size_16], &fibre_lane);    // Is there another packet start exactly one packet size later?
          if (next_packet_no != ((this_packet_no+1) % packets_per_sec)) continue;       // If so, it better look like the header for the next numbered packet on the same lane or we're out-o-here

          next_packet_no = unpackhdr(&dma_buf_16[loop+big_step_in], &fibre_lane);       // Is there another packet header exactly (packets_per_buff-3) packet sizes later? ie right near the buffer end?

          if (next_packet_no != ((this_packet_no+packets_per_buff-3) % packets_per_sec)) {      // This *could* be lots of monkeys typing but it's probable that the EDT cards DMA buffers have gone bad :(

// Might be a good place to write out the information needed to work out what we're seeing instead of trying to kick the EDT card
/*
            Current_GPStime = (INT64)arrive_time.tv_sec - GPS_offset;                   // What's the current time?
            if (Current_GPStime == GPStime_of_fail) {
              failures_this_sec++;                                                      // How many this sec have been bad?  If the EDT Card lost buffer sync, it will spit junk ~17 times per second
            } else {                                                                    // That depends on the buffer size of course.  If we're just seeing timeouts then there'll only be ~one per sec.
              failures_this_sec=1;                                                      // This is the first error this second.
              GPStime_of_fail = Current_GPStime;
            }

            if (failures_this_sec >= failures_allowed) {                                // Kick EDT Card in teeth.  Its DMA buffer pointers have probably failed!

              printf("k"); fflush(stdout);

              failures_this_sec=0;                                                      // This might not be strictly true (ie 0 fails), but if we just kicked the card, then don't kick it again too soon.

              edt_disable_ring_buffers(edt_p);                                          // Give us the valuable low memory (<4GB) back

              if (edt_configure_ring_buffers(edt_p, bufsize, numbufs, EDT_READ, NULL) == -1) {
                printf("Unable to configure %d ring-buffers of %d bytes\n", numbufs, bufsize);
                fflush(stdout);
                terminate = TRUE;                                                       // This is fatal.  Tell everyone to pack up and go home.
                pthread_exit(NULL);
              }

              edt_set_rtimeout(edt_p,1000);                                             // Set card to time out all reads after 1 second.  Probably not needed, but can't hurt right?

              edt_flush_fifo(edt_p) ;                                                   // Flush the input fifo.  We only want new stuff!

              edt_start_buffers(edt_p, numbufs) ;                                       // restart the transfers and allow only numbufs before stopping

            }
*/
            break;                                                                      // Whether the card is reset or not, this whole buffer is useless.
          }

          // we have ourselves a plausible looking buffer with two packets at the beginning checked, and one right near the end, all internally consistent.
          // We're happy to call 'loop' the first word of packet 'this_packet_no' in a good buffer of data from 'fibre_lane'.
          // It's no good to us though, if it doesn't have a one second clockover in it that we can sync on.

          offset_to_nxt_sec = ((packets_per_sec-this_packet_no) % packets_per_sec) * packet_size_8 + (loop*2);  // when do we expect the beginning of the new second?

          if (offset_to_nxt_sec >= bufsize) {						// The new second doesn't start inside this buffer.
            printf("u"); fflush(stdout);
            inc_clip( &health.seen_unusable );						// Increment the number of unusable packets we've seen
            break;									// Give up and get a new buffer.
          }

          // We did it!  We found a packet that contains the beginning of a fresh second.

          Current_GPStime = (INT64)arrive_time.tv_sec - GPS_offset;                     // This will be GPS timestamp that lives with this packet forever.  Convert linux to GPS time.
          if ( (int)arrive_time.tv_nsec > 950000000 ) {					// but the ntp clock might be slightly out, so if we're within 50mS of the *end* of a second according to our clock
            Current_GPStime++;								// we'll assume it's in the next actual second somewhere close to the beginning
          }

          // We only want to write the data from the beginning of the second. Not the whole buffer.
          memcpy( write_flip, dma_buf_8+offset_to_nxt_sec, written_to_flip=(bufsize-offset_to_nxt_sec) );       // Copy to the BEGINNING of the write buffer.

          sec_start_time = arrive_time;							// Time that the first buffer for this second is handed to the application
          sec_start2end = written_to_flip;						// and this is how many bytes of the new second were in that buffer (used for estimating the rollover time)

//          Current_GPStime_nsec = (int)arrive_time.tv_nsec - ((((written_to_flip*89)/37)*29)/15);		// It's only an estimate. Close enough for government work I hope!
//          if ( Current_GPStime_nsec > 500000000 ) Current_GPStime_nsec -= 1000000000;				// With a little clock drift, the packet may arrive before it's sent

          next_packet_no = this_packet_no + packets_per_buff + 1;                       // What packet will the next buffer start with? Careful. It may need tweaking.
          next_packet_ndx = loop + packet_size_16 - packet_remainder;                   // Where in the buffer will it start? Careful. It may need tweaking.
          if (next_packet_ndx >= packet_size_16) {                                      // We stepped into the buffer too far.
            next_packet_no--;                                                           // Should only need to back off one packet.
            next_packet_ndx -= packet_size_16;
          }
          next_packet_no %= packets_per_sec;                                            // There's almost certainly a second rollover correction needed here (so we do one)

          synced = TRUE;                                                                // We've begun a second of data and we're all synced up.  We shouldn't need to do this again until a data glitch.

          printf("\n%lld: found start of second for Rec%02d:%d.\n", Current_GPStime, (fibre_lane+3)/3, (fibre_lane % 3) );
          fflush(stdout);

          break;                                                                        // No point in carrying on the 'for' loop.
        }

        if (loop==packet_size_16) {							// If the 'for' loop finished (ie no 'break') and we didn't see a packet anywhere
          printf("j"); fflush(stdout);							// then this is junk!
          inc_clip( &health.seen_junk );						// Increment the number of junk packets we've seen
        }

      }

    }

//---------------- Thread shutdown code ------------------------

    pthread_mutex_unlock( &FlipBuffArray[wflip].Buff_mx );              // Release the lock as we shut down.  This should allow flip2buff to terminate too.

    edt_disable_ring_buffers(edt_p);                                    // Give us the valuable low memory (<4GB) back

    edt_close(edt_p) ;                                                  // Pack away the toys and put them back in the drawers for next time.

/*
    for ( loop=0; loop < raw_bufs_to_dump; loop++ ) {
      sprintf( my_debug_file, "3pip%d_%02d_%02d.raw", edt_channel, loop, raw_buf_for_dump );
      debugfiledesc = open( my_debug_file, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IWGRP | S_IRGRP | S_IROTH );
      if ( write( debugfiledesc, raw_bufs+(raw_buf_for_dump*bufsize), bufsize ) != bufsize ) printf( "Incomplete write\n" );
      close( debugfiledesc );

      if ( ++raw_buf_for_dump == raw_bufs_to_dump ) raw_buf_for_dump = 0;             // Cycle througn to the next buffer
    }
*/

    fflush(stdout);
    pthread_exit(NULL);
}

//---------------------------------------------------------------------------------------------------------------------------------------------------
// flip2buff - Accept flip buffers from edt2flip and place them in the main buffer queue.  Locate another buffer for edt2flip to use next time.
//---------------------------------------------------------------------------------------------------------------------------------------------------

void *flip2buff()
{

    INT64 latest_time;                                                  // GPS time of the latest buffer

    INT64 health_Buff_time;						// health (ie logging) copy of GPS time of last buffer
    INT64 health_last_Buff_time = 0;					// When did we last have a good second before this one?

    struct timespec health_sec_start_time;				// health (ie logging) copy of time that first packet for this second handed to us in linux format
    struct timespec now;
    monitor_udp_time.tv_sec = 0;
    INT64 health_GPS_start_sec;						// GPS conversion of the above linux seconds
    int health_GPS_start_nsec;						// and the fractional second component of above
    int health_prev_GPS_start_nsec = 0;					// and a copy of (above) from the previous second's data

    int health_sec_start2end;						// health (ie logging) copy of num bytes after start of second and before we recorded time stamp above.
    INT16 health_fibre_lane;						// health (ie logging) copy of current fibre
    int health_rec;							// health (ie logging) copy of receiver number [1-16]
    int health_fibre3;							// health (ie logging) copy of fibre 0, 1 or 2 on this receiver. (numbers are 0 based)
    int health_est_lag_time;						// The estimated lag time from the start of a second, until the first edt block is handed to us in nsec.

    int buff_ndx;                                                       // The OneSecBuff_ndx that the current flip buffer relates to.
    int new_ndx;                                                        // Used in the search for a new entry.  Eventually it will succeed, even if we need to kill good data.
    UINT8 *new_buff;                                                    // working storage for malloced block while we verify it.
    int flip = 0;                                                       // Start from flip buffer 0.  Every loop, we'll swap between 0 and 1.

    OneSecBuff_t *my;                                                   // Temporary pointer to the current one second buffer

    uint64_t bot32mask = 0xFFFFFFFF;                                    // Mask to only keep the bottom 32 bits of the GPS time
    int s_obs_id_ndx;                                                   // will be the index number into the metabin array for the correct obs_id for this second

//-------------------- Set up the multicast transmit for the health packets to 224.0.2.2:8003

    char *multicast_ip = "224.0.2.2";
    unsigned char ttl = 3;
    struct sockaddr_in addr;
    struct in_addr localInterface;

    int health_socket;

    // create what looks like an ordinary UDP socket
    if ( ( health_socket = socket( AF_INET, SOCK_DGRAM, 0) ) < 0) {
      perror("socket");
      terminate = TRUE;
      pthread_exit(NULL);
    }

    // set up destination address
    memset( &addr, 0, sizeof(addr) );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr( multicast_ip );
    addr.sin_port = htons( 8003 );					// Health port for medconv health packets

    setsockopt( health_socket, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl) );

    char loopch = 0;

    if (setsockopt( health_socket, IPPROTO_IP, IP_MULTICAST_LOOP, (char *) &loopch, sizeof(loopch) ) < 0) {
      perror("setting IP_MULTICAST_LOOP:");
      close( health_socket );
      terminate = TRUE;
      pthread_exit(NULL);
    }

    // Set local interface for outbound multicast datagrams. The IP address specified must be associated with a local, multicast-capable interface.

    localInterface.s_addr = inet_addr( conf.local_mc_if );

    if (setsockopt( health_socket, IPPROTO_IP, IP_MULTICAST_IF, (char *) &localInterface, sizeof(localInterface) ) < 0) {
      perror("setting local interface");
      close( health_socket );
      terminate = TRUE;
      pthread_exit(NULL);
    }

//-------------------- Fill up the initial values and values that won't change in the health packets

    health.message_type = 0x01;						// Health packet format.  Currently only 0x01 for 'announcement of good 1 second data arrival'
    health.medconv_state = 0x01;					// Current state of medconv process.  0x01 for 'awaiting new RRI receiver data' (Well it will be by the time I send this)

    health.last_GPS_time = 0;						// The GPS second assigned to the last good 1 second data block seen (before the current one). So far there hasn't been any.

    health.seen_unusable = 0;						// How many 'unusable' blocks seen since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
    health.seen_junk = 0;						// How many 'junk' blocks seen since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
    health.seen_badsync = 0;						// How many times did the decoding thread indicate bad or no sync since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
    health.seen_lostsync = 0;						// How many times did we lose edt block sync since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
    health.seen_other = 0;						// How many other warnings occurred since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)

    health.edt_unit = conf.edt_unit;					// EDT card unit number (0 or 1) for the two cards that are (or might be?) in a medconv server
    health.edt_channel = conf.edt_channel;				// EDT channel number (0, 1 or 2) for the 1st, 2nd or 3rd SFP socket (port) on the EDT card
    health.instance = conf.edt2udp_id;					// Unique medconv process instance for the system.  Will be 1 to 60 inclusive.

    strncpy ( health.hostname, conf.host, 10 );				// Copy the first 10 characters (incl null) of the hostname into the health packet
    health.hostname[9] = 0x00;						// In case something goes wrong (bug?) with the conf.host length, then force a null terminator on the health packet copy.

    health.pid = getpid();						// Process ID of this process on this server.
    health.build = BUILD;						// Software version number of the code generating this packet.

//-------------------- Get on with looking for 1 second data blocks

    usleep(500000);                                                     // Give edt2flip enough time to lock the mutex on flip buffer 0.  First packet can't be for at least 1 second anyway.

    printf("\nflip2buff started\n");
    fflush(stdout);

    while(TRUE) {
      pthread_mutex_lock( &FlipBuffArray[flip].Buff_mx );               // Get a lock on the mutex associated with the buffer that is being written to, and just finished when this lock succeeds.

      if (terminate) {
        pthread_mutex_unlock( &FlipBuffArray[flip].Buff_mx );           // It might be that the buffer isn't really filled and ready.  It's just the other thread releasing its mutex on abort.
        pthread_exit(NULL);                                             // so release our lock and abort
      }

      pthread_mutex_lock( &buff_array_mx );                             // We need unfettered access to the main array linked list.  Should be safe to just wait.  We have a whole second to do this.

      buff_ndx = FlipBuffArray[flip].OneSecBuff_ndx;                    // We'll be using this quite a lot.  If only for readability, let's make it a variable.

      my = &OneSecBuffArray[buff_ndx];					// We'll be using this quite a lot.  If only for readability, let's make it a variable.

      if ( my->Buff_ptr != FlipBuffArray[flip].Buff_ptr ) {             // ASSERT if these don't match.  We must have a bug.  It should have been there since the original Malloc.
        printf("\nASSERT: Flip buffer pointer doesn't match main array pointer\n");
        fflush(stdout);
        terminate = TRUE;
        pthread_mutex_unlock( &FlipBuffArray[flip].Buff_mx );           // Release the mutex so everyone can close down
        pthread_exit(NULL);
      }

      // Populate relevant entries in the metadata array

      latest_time = my->Buff_time = FlipBuffArray[flip].Buff_time;      // Copy the GPS time from the flip buffer to the time in the main buffer array.

      my->sec_start_time = FlipBuffArray[flip].sec_start_time;		// Copy the full linux time from the flip buffer to the main buffer array.
      my->sec_start2end = FlipBuffArray[flip].sec_start2end;		// Copy the number of bytes after the start of the second and before we got a chance to record the time stamp above.

      my->GPS_32 = (UINT32) ( my->Buff_time & bot32mask );              // Bottom 32 bits of GPS time. Used in network packets where upper 32 bits can be assumed.
      my->udp_ndx = my->GPS_32 & (UDP_BUFS-1);                          // which of the udp indexes is the right one for this buffer?

      my->fibre_lane = FlipBuffArray[flip].fibre_lane;                  // Save the lane. Later on, other threads will check if this has been changed and act appropriately
      my->rec = ( my->fibre_lane / 3 ) + 1;                             // Break fibre_lane up into receiver and which fibre on that receiver.  See unpackhdr() for more detail.  NB Integer maths.  Receivers numbers are 1 based
      my->fibre3 = my->fibre_lane + 3 - ( 3 * my->rec );                // as above.  Now we know if it was fibre 0, 1 or 2 on this receiver.  Receiver numbers are 1 based, *BUT* Fibre numbers are 0 based.

      s_obs_id_ndx = 0;         // look my->Buff_time up in table;                      Find the metabin array element for the correct obs_id

      my->obs_id = obs_meta[s_obs_id_ndx].obs_id;                       // Remember the obs_id associated with this buffer's second. If no observation in progress, then use the last one for now
//    my->obs_id = current_obs_id;                                      // WIP!!! later we'll use the right obs id, but for now just use the one from the command line

      for ( int inp = 0 ; inp < INPPERPACKET ; inp++ ) {                                        // Once for every input this receiver supports
        my->rf_input[inp] = obs_meta[s_obs_id_ndx].rf_input_map[my->rec-1][inp];                // Copy *this* receiver's list of Tile_ids sorted by order they appear in the RRI packets and place in the destination header
      }

      for ( int fchan = 0 ; fchan < CHANPERPACKET ; fchan++ ) {                                 // Once for each coarse channel.  Always expected to be 8.  Forced by the RRI packet format.
        my->sky_freq[fchan] = obs_meta[s_obs_id_ndx].sky_freq_map[my->fibre3][fchan];           // Copy *this* fibre's list of Sky Frequencies sorted by the order they appear in the RRI packets and place in the destination header
        my->multicast_dest[fchan] = obs_meta[s_obs_id_ndx].multicast_dest_map[my->fibre3][fchan];       // Copy *this* fibre's list of which multicast destinations it needs to send this buffer to, in the order they appear in RRI packets
      }

      my->Converted2udp = 0;                                            // It still needs to be convered into udp packets for the output
      my->Sent2nic = FALSE;                                             // It still needs to be send to the nic to multicast out on to the network

      my->Buff_locks = 0x00;                    // No one is holding read locks on this block (yet).  NB Doesn't apply if you have a full Mutex on the array like me now.
      my->Neededby = 0x03;                      // WIP!!!  Really needs to be filled with current 'Are we in ICS & Correlator modes?' flags!!!  For now set to the two threads that need to use this buffer

      // Copy relevant fields from this buffer's metadata for health and logging purposes later on (ie when we aren't holding mutex locks)

      health_Buff_time = my->Buff_time;					// GPS Time stamp attached by edt2flip thread
      health_sec_start_time = my->sec_start_time;			// time we first got a block with the new second
      health_sec_start2end = my->sec_start2end;				// How much data followed the start of second
      health_fibre_lane = my->fibre_lane;				// last fibre
      health_rec = my->rec;						// last receiver
      health_fibre3 = my->fibre3;					// last fibre (0,1,2) within receiver

      // Add the current write buffer to the linked list of all buffers

      OneSecBuffArray[OneSecBuff_last].Buff_next = buff_ndx;            // What *was* the most recent entry, now needs to point to me.
      OneSecBuffArray[buff_ndx].Buff_next = -1;                         // I, on the other hand, shouldn't point anywhere forward,
      OneSecBuffArray[buff_ndx].Buff_prev = OneSecBuff_last;            // but I need to point back to him,
      OneSecBuff_last = buff_ndx;                                       // and *I'm* now the most recent.

      // We've finish handling the full buffer he just gave us, but we need to find another buffer to give him back.
      // Try to find a completely spare buffer in the list.  ie everyone is finished with it AND it's been written to disk.  We'll reuse old buffers before asking for more RAM.

      new_ndx = OneSecBuff_first;                                       // Start with the oldest chronological block.
      while (new_ndx != -1) {                                           // While we're still looking at valid entries in the list
        if (OneSecBuffArray[new_ndx].Neededby == 0) break;              // Nobody still wants this one
        new_ndx = OneSecBuffArray[new_ndx].Buff_next;                   // Follow the linked list to the next one chronologically.
      }

      // If new_ndx != -1 then we already have one we can use, but maybe it *is* -1 and we still need to find somewhere to put the new data.

      if (new_ndx == -1 && OneSecBuff_inuse < OneSecBuff_max) {         // There were no completely free buffers but we're still allowed to assign a whole new one.

//        new_buff = (UINT8*) aligned_alloc(4096,OneSecBuff_Size);      // Try to get a fresh block of memory allocated that's aligned on a 4KB boundary
//        new_buff = (UINT8*) malloc(OneSecBuff_Size);
        if ( posix_memalign((void **)&new_buff,4096,OneSecBuff_Size+6) != 0 ) new_buff = NULL;

//      printf("m"); fflush(stdout);                                    // Debug output

        if (new_buff != NULL) {                                         // The malloc worked so we'll add this into the pool of buffers.  Last index in the array, but oldest chronologically.
          new_ndx = OneSecBuff_inuse++;                                 // Notice it is POSTFIX increment.  We now have 'n' number of them allocated, but the last one is 'n-1'.
          OneSecBuffArray[new_ndx].Buff_ptr = new_buff;                 // We'll be reusing this buffer a lot, so we need to store its address.
          OneSecBuffArray[new_ndx].Buff_next = OneSecBuff_first;        // We'll point to the one that *used* to be 'oldest'.
          OneSecBuffArray[new_ndx].Buff_prev = -1;                      // We don't have anyone before us in the linked list.
          OneSecBuff_first = new_ndx;                                   // and *we'll* be the new 'oldest'.  That's fair because we've never had any real data in this buffer.
        } else {
          printf("\nMalloc failed while attempting to assign buffer %d\n", OneSecBuff_inuse); fflush(stdout);           // Shouldn't be fatal, we just need to be more agressive about reusing an old one.
        }
      }

      // WIP!!! If new_ndx is still -1 then we should find one that doesn't *need* to be written to disk.  For now just take the oldest one not read locked.

      if (new_ndx == -1) {                                              // WIP!!! We need to be smarter than this, but for now just take the oldest one not read locked.
        new_ndx = OneSecBuff_first;                                     // Start with the oldest chronological buffer.
        while (new_ndx != -1) {                                         // While we're still looking at valid entries in the list
          if (OneSecBuffArray[new_ndx].Buff_locks == 0x00) {            // Does anyone have a read lock on this?
            printf("!"); fflush(stdout);                                // We've lost some data, but we can't keep it all
            break;                                                      // Is this a buffer that nobody is currently using? (ie read locked)
          }
          new_ndx = OneSecBuffArray[new_ndx].Buff_next;                 // Follow the linked list to the next one chronologically.
        }
      }

      if (new_ndx == -1) {                                              // ASSERT if we don't have a buffer to use yet.  There are supposed to be more buffers than threads that can get read locks
        printf("\nASSERT: No unlocked buffers found\n");
        fflush(stdout);
        terminate = TRUE;
        pthread_mutex_unlock( &FlipBuffArray[flip].Buff_mx );           // Release the mutex so everyone can close down
        pthread_exit(NULL);
      }

      // We've picked a buffer to use.  Now we need to remove it from the linked list.  If it was Malloced (above), then the poor thing only *just* made it into the linked list!
      // We know that there are at least three entries in the linked list, because we created 2 at the start-of-world and we've just added the flip buffer.
      // No need to test for special cases of 'Is the first also the last?' or 'Is the list empty?' etc.  There are only the 'first', 'last', and 'somewhere in the middle' cases to handle.

      if (new_ndx == OneSecBuff_first) {                                // We're reusing the oldest
        OneSecBuff_first = OneSecBuffArray[new_ndx].Buff_next;          // The one that the oldest points to, is now the oldest.
        OneSecBuffArray[OneSecBuff_first].Buff_prev = -1;               // That one now needs to point back to nowhere (ie -1)
      } else {
        if  (new_ndx == OneSecBuff_last) {                              // We're reusing the youngest
          OneSecBuff_last = OneSecBuffArray[new_ndx].Buff_prev;         // The one that the youngest points back to, is now the youngest.
          OneSecBuffArray[OneSecBuff_last].Buff_next = -1;              // That one now needs to point forward to nowhere (ie -1)
        } else {                                                        // We're reusing one somewhere inside the list
          OneSecBuffArray[OneSecBuffArray[new_ndx].Buff_prev].Buff_next = OneSecBuffArray[new_ndx].Buff_next;           // Point the 'next' for the one before me, to the one after me.
          OneSecBuffArray[OneSecBuffArray[new_ndx].Buff_next].Buff_prev = OneSecBuffArray[new_ndx].Buff_prev;           // Point the 'prev' for the one after me, to the one before me.
        }
      }

      OneSecBuffArray[new_ndx].Buff_time = 0;                           // The GPS time of the last data occupant of this buffer is no longer relevant.  Remove this so everyone knows it's gone.

      // The buffer has now been removed from the linked list.  Put the new buffer's details into the flip buffer array.

      FlipBuffArray[flip].OneSecBuff_ndx = new_ndx;                     // Remember where this flip buffer lives in the main array
      FlipBuffArray[flip].Buff_ptr = OneSecBuffArray[new_ndx].Buff_ptr; // Give the EDT thread his own copy of the pointer to RAM so he doesn't need to access OneSecBuffArray at all

      pthread_mutex_unlock( &buff_array_mx );                           // We have left the linked list in good shape.  Someone else can use it now.

      pthread_mutex_unlock( &FlipBuffArray[flip].Buff_mx );             // The flip buffer is now ready to be given back to the EDT thread with a pointer to clean RAM for him to use.

      flip ^= 0x01;                                                     // Flip the buffer!  If it *was* pointing to element zero, it's now pointing to element one and vice versa.

      OneSecBuff_Sec = latest_time;                                     // Set the global latest time to tell all the other threads that it's worth looking for a new second.

      // Let's log some details about how we have a complete new second of data that we're ready to use

      health_GPS_start_sec = (INT64)health_sec_start_time.tv_sec - GPS_offset;		// Convert the linux arrival time to GPS seconds
      health_GPS_start_nsec = (int) health_sec_start_time.tv_nsec;	// and grab the fractional second component

      printf( "\n%lld.%09d:", health_GPS_start_sec, health_GPS_start_nsec );	// Log the time the first edt packet arrived for this second before we tweak it

      if ( health_GPS_start_sec == (health_Buff_time-1) ) {		// If the wall clock still said it was the previous second (presumably right near the end of it)
        health_GPS_start_sec++;						// then convert it to be the beginning of the next second
        health_GPS_start_nsec -= 1000000000;				// and give it a -ve 'nsec' fractional part
      }

      // We already know 'when' during the wall-clock second the full EDT buffer (containing the second roll-over) was given to us.
      // Can we use that time *and* the amount of data following the roll-over (we were given at the same time) to estimate when we would have seen the second roll-over if there was no extra data after?
      // Turns out each character takes ~4.650432 nSec to arrive.  (Calculated by best fit of 100 samples observed data on VCS01).
      // I'd rather stick with integer maths though and that is around 2581/555ths.  I can't just multiply by 2581 though because that will likely exceed an int32.  Let's break this into chunks.
      // * 89 / 37 * 29 / 15 is pretty darn close. (~4.650450) and won't overflow an int32 at any point so long as the buffer remaining is less than 23MB which is bigger than the whole buffer size.

      health_est_lag_time = ((( (health_sec_start2end*89) /37)*29)/15);	// The estimated lag time from the start of a second, until the first edt block is handed to us in nsec
      health_GPS_start_nsec -= health_est_lag_time;			// and remove the estimated extra time the receiver and EDT card spend sending us data in the new second

      if ( health_GPS_start_sec != health_Buff_time ) {			// If these don't match now, something we don't understand is happening!
        health_GPS_start_nsec = -1000000000;				// so set an impossible nsec time to warn M&C via the health packets
      }

      // Disable this behaviour for now
      //if ( ( health_GPS_start_nsec >= too_late_ns ) && ( health_prev_GPS_start_nsec >= too_late_ns ) ) {	// If both this second's data, and the previous second's, arrive after the allowed arrival lag
      //  kick_edt = TRUE;						// Request that we should reset all the EDT card ring buffers
      //}

      printf( " %lld:%10d, lost=%lld, Rec%02d:%d, lane=%d, pid=%d, id=%d, %s, %d, %d, %d, offset=%d",
        health_GPS_start_sec,
        health_GPS_start_nsec,
        (health_Buff_time - health_last_Buff_time - 1),
        health_rec,
        health_fibre3,
        health_fibre_lane,
        health.pid,
        conf.edt2udp_id,
        conf.host,
        conf.edt_unit,
        conf.edt_channel,
        BUILD,
        health_sec_start2end );

      fflush(stdout);

      // Now populate the packet structure directly in memory

      health.GPS_time = health_Buff_time;
      health.arrival_offset = health_GPS_start_nsec;
      health.last_GPS_time = health_last_Buff_time;
      health.receiver = health_rec;
      health.fibre3 = health_fibre3;
      health.lane = health_fibre_lane;

      clock_gettime(CLOCK_REALTIME, &now);
      if(now.tv_sec - monitor_udp_time.tv_sec > 1) {
        if(monitor_udp_count - monitor_udp_last == 0) {
          health.medconv_state &= ~(1 << 1);
        } else {
          health.medconv_state |= 1 << 1;
        }
        monitor_udp_last = monitor_udp_count;
        monitor_udp_time = now;
      }

      // Now send the multicast udp health packet

      if ( sendto( health_socket, &health, sizeof(health), 0, (struct sockaddr *) &addr, sizeof(addr) ) < 0) {
        printf( "\nFailed to send health packet" );
        fflush(stdout);
      }

      // Now reset the error counts.  NB: There is a small window where we may lose an increment, but they are only a guide and not critical to know, so ignore that possibility
      health.seen_unusable = 0;						// How many 'unusable' blocks seen since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
      health.seen_junk = 0;						// How many 'junk' blocks seen since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
      health.seen_badsync = 0;						// How many times did the decoding thread indicate bad or no sync since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
      health.seen_lostsync = 0;						// How many times did we lose edt block sync since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)
      health.seen_other = 0;						// How many other warnings occurred since the last health packet (clips at 255.  Treat as 'zero' or 'non-zero' flag)

      health_last_Buff_time = health_Buff_time;				// Now *this* second is the *last* good second

      health_prev_GPS_start_nsec = health_GPS_start_nsec;		// and this second's nsec arrival time is the previous recorded one.  NB: There's no guarantee these are actually consecutive but we don't really care.

      // End of health packet sending

/*
struct timespec debug_time;
clock_gettime( CLOCK_REALTIME, &debug_time);
printf ( "%03d.%06d Stored   : %lld:%lld:%lld\n",
(int)(debug_time.tv_sec % 1000),
(int)(debug_time.tv_nsec / 1000),
OneSecBuff_Sec,
OneSecBuff_Sec-OneSecBuff_udp,
OneSecBuff_Sec-udp_upto );
*/
    }
}

//---------------------------------------------------------------------------------------------------------------------------------------------------
// buff2udp - Locate 5+5i bit buffers that need to be corner turned and converted to 8+8i and generate udp packets ready to send
//---------------------------------------------------------------------------------------------------------------------------------------------------

void *buff2udp()
{

    INT64 upto=10000;                                           // GPS time of the last second we have looked at.  Unless checkifwriteneeded is true, only times after this are worth looking at.

    BOOL buff_held = FALSE;                                     // We aren't currently holding a one sec buffer with a read lock
    int our_buff = 0;                                           // *If* we have a buffer held, which one is it?
    int nxt_wbuff;                                              // The next buffer we should convert

    UINT64 lock_mask = 1 << 0;                          // Leave room below us for all the locks of the communications threads.
    UINT64 unlock_mask = ~lock_mask;                            // Straight bit inversion of the lock mask.

    OneSecBuff_t *myOSBA;                                       // Local pointer to the particular buffer we're dealing with

    volatile UINT64 working64=0;
    UINT32 *working32H_ptr;
    UINT32 *working32L_ptr;

    working32H_ptr = (UINT32 *) &working64;
    working32L_ptr = working32H_ptr++;

    UINT32 header1, header2;

    int subsec = 0;                                                     // loop counter used for each time step.
    int fchan = 0;                                                      // loop counter used for each coarse channel.
    int inp = 0;                                                        // loop counter used for every input this receiver puts into a packet.  Forced by the RRI packet format to go to 16.
    int sample = 0;                                                     // loop counter used for every one of the 2048 time samples in a packet

    UINT16 *d_subsec_ptr;                                               // The pointer to the first voltage data for the current subsec.  We start on the first for this second
    UINT16 *d_sample_ptr;                                               // The pointer to the voltage data for the current time sample within this subsec for the 1st coarse chan and 1st input chain
    UINT16 *dest_ptr;                                                   // Reset our working pointer back to the 1st coarse channel and 1st input, but for the next sample time.

    int step = sizeof(struct mwa_udp_packet) >> 1;                      // Step down one udp packet.  This will be applied to UINT16 pointers so needs to be in units of 16 bits
    int d_sample_step = 1;                                              // Step right a single (16 bit) UINT16
    int d_subsec_step = step * CHANPERPACKET * INPPERPACKET;            // Step down a whole subseconds worth.  ie 128 udp packets

    UINT32 *source_ptr;

//    struct timespec start_time;                                               // Used for testing conversion performance
//    struct timespec end_time;                                         // Used for testing conversion performance
//    struct timespec dtime[9];

    UINT16 ten2sixteen[1024];
    UINT8 real, imag;

    for ( int loop = 0 ; loop < 1024 ; loop++ ) {
      real = loop & 0b11111 ;
      if ( ( real & 0b10000 ) == 0b10000 ) real |= 0b11100000;
      imag = ( loop >> 5 ) & 0b11111 ;
      if ( ( imag & 0b10000 ) == 0b10000 ) imag |= 0b11100000;
      ten2sixteen[ loop ] = imag<<8 | real;
//    printf ( "%d is r=%d/%d i=%d/%d %#06x\n", loop, real, real-256, imag, imag-256, ten2sixteen[ loop ] ) ;
    }

    printf("buff2udp started\n");
    fflush(stdout);

    while ( !terminate ) {                                              // Keep going until we are told to stop

      if ( buff_held || checkifwriteneeded || OneSecBuff_Sec > upto ) { // If we have any reason to need access to the main array linked list

//-------------------- Locked buffer array section --------------------

//clock_gettime( CLOCK_REALTIME, &dtime[7]);

        pthread_mutex_lock( &buff_array_mx );                           // get a lock on the metadata array

//clock_gettime( CLOCK_REALTIME, &dtime[8]);

        nxt_wbuff = OneSecBuff_first;                                   // We have no idea what buffer we should work on next, so start looking from the oldest

        if (buff_held) {
          OneSecBuffArray[our_buff].Buff_locks &= unlock_mask;          // Remove our read lock on the buffer
          OneSecBuffArray[our_buff].Neededby &= unlock_mask;            // Remove any flags saying that we still need this block
          OneSecBuffArray[our_buff].Converted2udp = 2;                  // This is the buffer we just converted

          if ( OneSecBuff_udp < OneSecBuffArray[our_buff].Buff_time )   // Signal to the other thread to tell it which is the latest second that is finished.  NB that it is possible that one earlier second is still in progress
            OneSecBuff_udp = OneSecBuffArray[our_buff].Buff_time;       // on a different thread running the same function and when that completes we don't want the time to go backwards

          buff_held = FALSE;                                            // and now we don't have a read lock any more

/*
{
printf ( "%03d.%06d %03d.%06d %03d.%06d %03d.%06d %03d.%06d %03d.%06d %03d.%06d %03d.%06d %03d.%06d %lld\n",
(int)(dtime[0].tv_sec % 1000),
(int)(dtime[0].tv_nsec / 1000),
(int)(dtime[1].tv_sec % 1000),
(int)(dtime[1].tv_nsec / 1000),
(int)(dtime[2].tv_sec % 1000),
(int)(dtime[2].tv_nsec / 1000),
(int)(dtime[3].tv_sec % 1000),
(int)(dtime[3].tv_nsec / 1000),
(int)(dtime[4].tv_sec % 1000),
(int)(dtime[4].tv_nsec / 1000),
(int)(dtime[5].tv_sec % 1000),
(int)(dtime[5].tv_nsec / 1000),
(int)(dtime[6].tv_sec % 1000),
(int)(dtime[6].tv_nsec / 1000),
(int)(dtime[7].tv_sec % 1000),
(int)(dtime[7].tv_nsec / 1000),
(int)(dtime[8].tv_sec % 1000),
(int)(dtime[8].tv_nsec / 1000),
OneSecBuffArray[our_buff].Buff_time );
}
*/
          if (!checkifwriteneeded)                                      // if we don't need to worry about someone retrospectively triggering conversion of old buffers
            nxt_wbuff = OneSecBuffArray[our_buff].Buff_next;            // then we can take a shortcut and only start looking at buffers later than the last one we did.
        }

        while (nxt_wbuff != -1) {                                       // while I'm still looking at valid buffers
          upto = OneSecBuffArray[nxt_wbuff].Buff_time;                  // update the latest time we are up to
          if ( OneSecBuffArray[nxt_wbuff].Converted2udp == 0 ) break;   // if this is the oldest one that needs to be converted into udp packets then break out.  This one will be our customer.
          nxt_wbuff = OneSecBuffArray[nxt_wbuff].Buff_next;             // Follow the linked list to the next one chronologically.
        }

        if (nxt_wbuff != -1) {                                          // We found a buffer that needs converting!
          OneSecBuffArray[nxt_wbuff].Converted2udp = 1;                 // Say that we are in progress, but not finished, converting this second
          OneSecBuffArray[nxt_wbuff].Buff_locks |= lock_mask;           // Get a read lock on that buffer

          buff_held = TRUE;                                             // Remember that we have the lock so we can release it later
          our_buff = nxt_wbuff;                                         // and remember which buffer it was

//clock_gettime( CLOCK_REALTIME, &dtime[0]);

        } else {
          checkifwriteneeded = FALSE;                                   // Well we checked and there is nothing (more) that needs to be converted so clear flag.
        }

        pthread_mutex_unlock( &buff_array_mx );                         // release our lock on the metadata array

//clock_gettime( CLOCK_REALTIME, &dtime[1]);

//-------------------- End of Locked buffer array section --------------------

        if (buff_held) {                                                // If we have found a buffer that we need to convert...

//-------------------- Start of conversion step --------------------

          myOSBA = &OneSecBuffArray[our_buff];                          // We'll be using this quite a lot.  If only for readability, let's make it a variable.

//          set a global "8 bit buffers deleted up to" GPS_time?

//---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//      udp packet order within the 80000 packets for this second is (slowest to fastest changing):
//        subsec_time [0...624]  followed by
//        8 coarse channels IN THE ORDER CONTAINED IN THE RRI RECEIVER PACKET followed by
//        16 rf_inputs IN THE ORDER CONTAINED IN THE RRI RECEIVER PACKET
//---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

          struct mwa_udp_packet *myh = udpbuff[myOSBA->udp_ndx];                        // udpbuff is an array of pointers to blocks of 80000 udp packets.  The least few (4?) bits of the GPS time is used as an index

          d_subsec_ptr = myh->volts;                                                    // The pointer to the first voltage data for the current subsec.  We start on the first for this second

          source_ptr = (UINT32*) (myOSBA->Buff_ptr + 6);                                // Buff_ptr points to the beginning of the RRI data for this second, but we want a pointer to 32 bits of the payload (ie 6 bytes in)

//INT16 which_fibre =-1;
//if ( unpackhdr((UINT16 *)myOSBA->Buff_ptr, &which_fibre ) != 0 ) printf( "********** Bad Packet **********\n" );
//printf( "%d:%lld:%lld:%lld:%lld\n",
//which_fibre,
//OneSecBuff_Sec,
//OneSecBuff_Sec-myOSBA->Buff_time,
//OneSecBuff_Sec-OneSecBuff_udp,
//OneSecBuff_Sec-udp_upto );

          for ( subsec = 0 ; subsec < SUBSECSPERSEC ; subsec++ ) {                      // Once for each time step.  Always expected to be 625 per second

//if ( subsec ==   0 ) clock_gettime( CLOCK_REALTIME, &dtime[2]);
//if ( subsec == 125 ) clock_gettime( CLOCK_REALTIME, &dtime[3]);
//if ( subsec == 250 ) clock_gettime( CLOCK_REALTIME, &dtime[4]);
//if ( subsec == 375 ) clock_gettime( CLOCK_REALTIME, &dtime[5]);
//if ( subsec == 500 ) clock_gettime( CLOCK_REALTIME, &dtime[6]);

            for ( fchan = 0 ; fchan < CHANPERPACKET ; fchan++ ) {                       // Once for each coarse channel.  Always expected to be 8.  Forced by the RRI packet format.
              for ( inp = 0 ; inp < INPPERPACKET ; inp++ ) {                            // Once for every input this receiver puts into a packet.  Forced by the RRI packet format to be 16.

                myh->packet_type = 0x20;                                                // Packet type (0x20 == 2K samples of RRI Voltage Data in complex 8 bit real + 8 bit imaginary format)
                myh->freq_channel = myOSBA->sky_freq[ fchan ];                          // The current coarse channel frequency number [0 to 255 inclusive]
                myh->rf_input = htons( myOSBA->rf_input[ inp ] );                       // maps to tile/antenna and polarisation (LSB is 0 for X, 1 for Y) *NETWORK ORDER*
                myh->GPS_time = htonl( myOSBA->GPS_32 );                                // [second] GPS time of packet (bottom 32 bits only) *NETWORK ORDER*
                myh->subsec_time = htons( subsec );                                     // count from 0 to PACKETS_PER_SEC - 1 (from header)  Typically PACKETS_PER_SEC is 625 in MWA *NETWORK ORDER*
                myh->spare1 = 0x00;                                                     // spare padding byte.  Reserved for future use.  Fill with a zero for now.

                myh->edt2udp_id = conf.edt2udp_id;                                      // Which edt2udp instance generated this packet and therefore a lookup to who to ask for a retransmission (0 implies no retransmission possible)

                myh->edt2udp_token = htons( fchan << 4 | inp );                         // value to pass back to this edt2udp instance to help identify source packet.  A token's value is constant for a given source rf_input and freq_channel for entire sub-observation *NETWORK ORDER*
                myh->spare2[0] = 0x00;                                                  // Spare bytes for future use
                myh->spare2[1] = 0x00;                                                  // Spare bytes for future use

                myh++;                                                                  // Move to the next udp packet within this output buffer

              }
            }

            d_sample_ptr = d_subsec_ptr;                                                // The pointer to the voltage data for the current time sample within this subsec for the 1st coarse chan and 1st input chain

            for ( sample = 0 ; sample < SAMPLES_PER_PACKET ; sample++ ) {               // 2048 samples to 8+8i bits, and copy to an xfer buffer composed of n seconds x 625 blocks x 16 signal chains x 8 coarse channels x 2048 samples x 2 bytes (or 128 packets of 4k + header per 1600000 nsecs)

              dest_ptr = d_sample_ptr;                                                  // Reset our working pointer back to the 1st coarse channel and 1st input, but for the next sample time.

//              for ( fchan = 0 ; fchan < CHANPERPACKET ; fchan++ ) {                     // Once for each coarse channel.  Always expected to be 8.  Forced by the RRI packet format.
              for ( fchan = 0 ; fchan < WORKINGCHAN ; fchan++ ) {                     // Once for each coarse channel.  Always expected to be 8.  Forced by the RRI packet format.

// up-promote a 20 byte block into 16 shorts and place one each in a destination UDP packet

//---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//      The samples for the 16 rf signal chains from this receiver (each 5 bit real + 5 bit imaginary) makes a logical source block of 160 bits that go together.
//      Rather than do smaller memory loads, the 160 bits will be picked up by five 32 bit reads into a 64 bit working register. Right shifts and bit masks will be used to group bits 10 at a time.
//      As 10 bit sets are used and the high order 32 bits becomes free, a new 32 bit read will repopulate it in preparation for more right shifts and bit masks.
//      The 10 bits will be used as an index into an array of 16 bit short ints which is precomputed to contain BOTH the 8 real + 8 imaginary version of the 5r+5i numbers.
//      The precomputed table may, or may not, reverse the real/imaginary order and may, or may not, chose to fill either the high or the low 5 bits of the 8 bit numbers.  Sign extension may also be used
//---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

                *working32L_ptr = *source_ptr++;                                                // Pick up the low order 32 bits of data which contains the first sections of 5+5i bit samples.
                *working32H_ptr = *source_ptr++;                                                // Pick up the high order 32 bits of data which contains the next sections of 5+5i bit samples

                                                                                                //  empty, awaiting, used.  Number of bits in each group in the 64 bit working register after line of code executed.
                *dest_ptr           = ten2sixteen[ (working64       ) & 0b1111111111 ];         //       0 54 10        NB.  We don't need to do a right shift at the start because we're already aligned
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      10 44 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      20 34 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      30 24 10

                working64 >>= 2;                                                                //      32 24  8        If we just shift over another 2 bits, we have room for a fresh 32 high order bits
                *working32H_ptr = *source_ptr++;                                                //       0 56  8        This will replace the 32 bits of zeros currently in the top 32 bits of working64

                *(dest_ptr += step) = ten2sixteen[ (working64 >>=  8) & 0b1111111111 ];         //       8 46 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      18 36 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      28 26 10

                working64 >>= 4;                                                                //      32 26  6        Shift another 4 and we can read in a fresh 32 bits into the top of working64
                *working32H_ptr = *source_ptr++;                                                //       0 58  6

                *(dest_ptr += step) = ten2sixteen[ (working64 >>=  6) & 0b1111111111 ];         //       6 48 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      16 38 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      26 28 10

                working64 >>= 6;                                                                //      32 28  4        Shift another 6 and we can read in a fresh 32 bits into the top of working64
                *working32H_ptr = *source_ptr++;                                                //       0 60  4

                *(dest_ptr += step) = ten2sixteen[ (working64 >>=  4) & 0b1111111111 ];         //       4 50 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      14 40 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      24 30 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      34 20 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>= 10) & 0b1111111111 ];         //      44 10 10
                *(dest_ptr += step) = ten2sixteen[ (working64 >>  10)                ];         //      54  0 10        NB. We don't need to save the right shifted buffer.  We're throwing it away soon.

                dest_ptr += step;                                                               // Line ourselves up with the right part of the next packet for the next coarse channel
              } // We've finished the source packet of 168 bytes, and populated one column of voltages in 128 destination packets

              rri2udp++;                                                                        // That's one more rri packet processed.  Equivalent in work to 1/16 of the udp packet generated

              source_ptr += (CHANPERPACKET - WORKINGCHAN) * 5;					// If we are only writing a subset of the 8 channels, then we need to skip some data

              header1 = *source_ptr++;
              header2 = *source_ptr++;          // We need to step over the 16 bits of checksum, and the 3 x 16bit header of the next source packet.  source_ptr is a pointer to UINT32 so that's just +=2

              if ( (( header1 >> 16 ) != 0x0800) & (subsec != 624) & (sample != 2047) ) {
                printf( "Bad sync subs=%d, smpl=%d.  Hdr1=%d, Hdr2=%d\n", subsec, sample, header1, header2 );
                fflush(stdout);
                inc_clip( &health.seen_badsync );							// Increment the number of times we lost sync while promoting packets
              }

              d_sample_ptr += d_sample_step;                                                    // We step right a single time step and point to the 1st input and channel for the next sample time (not whole subsec)

            }

            d_subsec_ptr += d_subsec_step;                                                      // The pointer to the first voltage data for the current subsec.  We're moving to the next subsec, so we step forward 128 packets

          }

//-------------------- End of conversion step --------------------

        }

      } else {                                                          // There is nothing exciting happening
        usleep(1000);                                                   // Have a nap for 5ms.
      }

    }

    rri2udp += packets_per_sec;                                         // Lie to udp2nic about how far ahead we are so he doesn't wait forever for us to get a second ahead of him
    pthread_exit(NULL);                                                 // We fell out of the while loop, so they must want us to terminate

}

//---------------------------------------------------------------------------------------------------------------------------------------------------
// udp2nic - Send pending udp packets out the NIC.
//---------------------------------------------------------------------------------------------------------------------------------------------------

#define UDP_BASE_ADDR "239.255.90.%d"
#define UDP_BASE_PORT (59000)

void *udp2nic()
{
    printf("udp2nic started\n");
    fflush(stdout);

//    INT64 udp_upto = 10000;                                     // GPS time of the last second we have looked at.  Unless checkifwriteneeded is true, only times after this are worth looking at.

    BOOL buff_held = FALSE;                                     // We aren't currently holding a one sec buffer with a read lock
    int our_buff = 0;                                           // *If* we have a buffer held, which one is it?
    int nxt_wbuff;                                              // The next buffer we should convert

    UINT64 lock_mask = 1 << 1;                                  // Leave room below us for all the locks of the communications threads.
    UINT64 unlock_mask = ~lock_mask;                            // Straight bit inversion of the lock mask.

    int udp_2_send;
    int udp_sent;
    int allowed_to_send = 0;
    int try_to_send;
    int actually_sent;

//    INT64 allowed_to_send_ever = 0;
    INT64 actually_sent_ever = 0;

    int fchan;

    OneSecBuff_t *myOSBA;                                                               // Local pointer to the particular buffer we're dealing with

//---------- Set up the destination addresses sendmmsg() ----------

    struct sockaddr_in msg_name_all[CHANPERSYSTEM+1];                                   // This is where we'll store every possible destination addresses used by the system (1 based)
    struct sockaddr_in msg_name_this_sec[CHANPERPACKET];                                // This is where we'll store the eight socket addresses used by the current second of data (0 based)
    struct sockaddr_in *mn;                                                             // temporary working pointer to the current msg_name

    char multicast_ip[64] = {0};                                                        // Room for the name of the destination address as a dotted quad string

    for ( int loop = 0 ; loop <= CHANPERSYSTEM ; loop++ ) {                             // Step through number 0 plus all 24 channels.  NB 1 based so 1 to 24 inclusive.  0 is for future use for ics or something

      mn = &msg_name_all[ loop ];                                                       // Make a temporary pointer to the current channel (ie msg_name)
      memset( mn, 0, sizeof( struct sockaddr_in ) );                                    // Zero any data that's already there

      mn->sin_family = AF_INET;                                                         // IPv4 in use

      sprintf( multicast_ip, UDP_BASE_ADDR, loop );                                     // Construct the dotted quad for each channel

//printf( "%d:\"%s\"\n", loop, multicast_ip );

      mn->sin_addr.s_addr=inet_addr(multicast_ip);                                      // Convert to addr format and store

      mn->sin_port = htons(UDP_BASE_PORT + loop);                                       // ...and we need a port number starting in a range we control (59001 - 59024?)

    }

/*
//---------- debug only!  Remove for production! ----------
msg_name_all[ 9 ].sin_addr.s_addr = msg_name_all[ 10 ].sin_addr.s_addr;			// Debug only.  Must be removed for production.  This will force coarse channel 9 to send its data to where coarse channel 10 will (also) go
msg_name_all[ 9 ].sin_port = msg_name_all[ 10 ].sin_port;				// The result will be no data to mwax09 and double data to mwax10!
printf( "Redirecting multicast data from chan09 to chan10\n" );				// WIP REMOVE THESE LINES!!!
*/
//---------- Set up the control arrays for sendmmsg() ----------

    struct mmsghdr *UDP_msg = calloc ( UDP_PER_MC, sizeof( struct mmsghdr ) );          // Memory for 80000 udp mmsghdrs.  Set everything to zero.
    struct iovec *UDP_iov = calloc ( UDP_PER_MC, sizeof( struct iovec ) );              // Memory for 80000 udp scatter gather addresses.  Set everything to zero.

    for ( int loop = 0 ; loop < UDP_PER_MC ; loop++ ) {                                 // Do individual initialization of each UDP packet

      UDP_msg[loop].msg_hdr.msg_name = &msg_name_this_sec[((loop & 0b01110000)>>4)];    // Three bits in 'loop' map to the coarse channel index which in turn maps to which multicast address we need for this packet
      UDP_msg[loop].msg_hdr.msg_namelen = sizeof( struct sockaddr_in );                 // size of address.  Will remain constant.

      UDP_msg[loop].msg_hdr.msg_iov = &UDP_iov[loop];                                   // Point to corresponding iovec.  We have a one-to-one mapping because we aren't scatter gathering.
      UDP_msg[loop].msg_hdr.msg_iovlen = 1;                                             // No scatter gather. The whole udp packet is stored in one chunk.

//    UDP_iov[loop].iov_base = ;                                                        // Needs updating each second so we can't do it here!
      UDP_iov[loop].iov_len = sizeof(mwa_udp_packet_t);                                 // All the packets will be the same length so we may as well just set this up once and use it forever
    }

//---------- Set up the 'socket' we will use for all this traffic ----------

    int sockfd;

    struct in_addr localInterface;                                                      // We'll need this to bind to a particular outgoing NIC interface on the .90. network

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);                                            // We want to use IPv4 and UDP

    if (sockfd == -1) {
      perror("socket()");
      exit(1);
    }

    unsigned char ttl=3;
    setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,sizeof(ttl));                 // Set the 'time to live' as 3.  That should be enough unless we add lots of network hops

    char loopch=0;
    if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0) {       // Force OFF multicast loop back.  We don't need to listen to our own babble!
      perror("setting IP_MULTICAST_LOOP:");
      close(sockfd);
      exit(1);
    }

    localInterface.s_addr = inet_addr( conf.local_if );

    if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface, sizeof(localInterface)) < 0) {
      perror("setting local interface");
      exit(1);
    }

//    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
//      perror("connect()");
//      exit(EXIT_FAILURE);
//    }


//    open up a regular UDP receiver port for receiving NAKs
//    clear all messages from it (if any) for startup.

////////////////////////////////////////////////////////////////

    printf("udp2nic initialized\n");
    fflush(stdout);

    while ( !terminate ) {                                              // Keep going until we are told to stop

      if ( buff_held || OneSecBuff_udp > udp_upto ) {                   // If we have any reason to need access to the main array linked list

//-------------------- Locked buffer array section --------------------

        pthread_mutex_lock( &buff_array_mx );                           // get a lock on the metadata array

        if (buff_held) {
          OneSecBuffArray[our_buff].Buff_locks &= unlock_mask;          // Remove our read lock on the buffer
          OneSecBuffArray[our_buff].Neededby &= unlock_mask;            // Remove any flags saying that we still need this block
          OneSecBuffArray[our_buff].Sent2nic = TRUE;                    // This is the buffer we just transmitted
          udp_upto = OneSecBuffArray[our_buff].Buff_time;               // update the latest time we are up to
          buff_held = FALSE;                                            // and now we don't have a read lock any more
/*
{
struct timespec debug_time;
clock_gettime( CLOCK_REALTIME, &debug_time);
printf ( "%03d.%06d Sent     : %lld\n",
(int)(debug_time.tv_sec % 1000),
(int)(debug_time.tv_nsec / 1000),
OneSecBuffArray[our_buff].Buff_time );
}
*/
        }

        nxt_wbuff = OneSecBuff_first;                                   // We have no idea what buffer we should work on next, so start looking from the oldest

        while (nxt_wbuff != -1) {                                       // while I'm still looking at valid buffers

          if ( !OneSecBuffArray[nxt_wbuff].Sent2nic ) break;            // We've found the earliest chronological buffer that hasn't been send to the nic yet, so we stop looking at buffers later in time

          nxt_wbuff = OneSecBuffArray[nxt_wbuff].Buff_next;             // Follow the linked list to the next one chronologically.
        }

        if (nxt_wbuff != -1) {                                          // We found a buffer that needs sending to the nic!
          if ( OneSecBuffArray[nxt_wbuff].Converted2udp == 2 ) {        // but is it converted to 8 bits and ready to go yet?
            OneSecBuffArray[nxt_wbuff].Buff_locks |= lock_mask;         // Get a read lock on that buffer
            buff_held = TRUE;                                           // Remember that we have the lock so we can release it later
            our_buff = nxt_wbuff;                                       // and remember which buffer it was
/*
{
struct timespec debug_time;
clock_gettime( CLOCK_REALTIME, &debug_time);
printf ( "%03d.%06d Sending  : %lld\n",
(int)(debug_time.tv_sec % 1000),
(int)(debug_time.tv_nsec / 1000),
OneSecBuffArray[our_buff].Buff_time );
}
*/
          }
        }

        pthread_mutex_unlock( &buff_array_mx );                         // release our lock on the metadata array

//-------------------- End of Locked buffer array section --------------------

        if (buff_held) {                                                                // If we have found a buffer that we needs to be sent to the nic...

//-------------------- Start of conversion step --------------------

//          get start time from wall clock

          myOSBA = &OneSecBuffArray[our_buff];                                          // We'll be using this quite a lot.  If only for readability, let's make it a variable.

//printf( "(send:%lld)\n", myOSBA->Buff_time );

          for ( fchan = 0 ; fchan < CHANPERPACKET ; fchan++ ) {                         // Once for each coarse channel in this second.  Always expected to be 8, but may not be the same 8 as last time...or ever seen before!
            msg_name_this_sec[fchan] = msg_name_all[myOSBA->multicast_dest[fchan]];     // We have 24 destination addresses preprepared.  Which 8 are applicable for this second and in which order?
          }

          udp_2_send = UDP_PER_MC;                                                      // We need to send this many to complete this second
          udp_sent = 0;                                                                 // So far we haven't sent any but give us a chance, we've only just begun this second

          struct mwa_udp_packet *myh = udpbuff[myOSBA->udp_ndx];                        // udpbuff is an array of pointers to blocks of 80000 udp packets.  Make myh a pointer to the first udp for this second's block

          for ( int loop = 0 ; loop < UDP_PER_MC ; loop++ ) {                           // Do individual initialization of each UDP packet for this second
            UDP_iov[loop].iov_base = myh;
            myh++;                                                                      // All seconds are sharing the one UDP_iov array so we need to update every pointer to a packet
          }


          while (udp_2_send > 0) {                                                      // There are more packets to go this second

/*
            while ( allowed_to_send_ever <= actually_sent_ever ) {                      // but we've sent all the one we've already decided we are allowed to

//            check for and send all retransmissions                                    // These are not counted in the packets per second count.  Only *new* packets are.

//              allowed_to_send = UDP_PER_MC;                                           // For now, we'll just dump the packets on the line without any bandwidth limit.  We'll do that by saying that we can send them all

              allowed_to_send_ever = (rri2udp - packets_per_sec)>>4;                    // We want to be exactly one second behind (ie 1280000 packets) and there are 16 rri packets per udp packet so '>>4'

              if ( allowed_to_send_ever <= actually_sent_ever ) YIELD;                  // if there's *still* nothing to do, then chillax a bit

            }

            allowed_to_send = allowed_to_send_ever - actually_sent_ever;                //
*/
            allowed_to_send = UDP_PER_MC;                                               // For now, we'll just dump the packets on the line without any bandwidth limit.  We'll do that by saying that we can send them all


            try_to_send = udp_2_send;                                                   // Begin by assuming we can send everything left for this second
            if ( try_to_send > MAX_UDP_PER_CALL ) try_to_send = MAX_UDP_PER_CALL;       // If that's too big a mouthful for one call, then lower our attempt for this time through the loop
            if ( try_to_send > allowed_to_send ) try_to_send = allowed_to_send;         // If that number would exceed the bandwidth we're trying to stay under, then don't send them all this time

//if ( ((udp_sent & 0b01110000)>>4) > 5 ) {
//  actually_sent = 1;
//} else {
            if ( ( actually_sent = sendmsg(sockfd, (const struct msghdr *) &UDP_msg[udp_sent], MSG_DONTWAIT) ) > 0) actually_sent = 1;
//}

//            actually_sent = sendmmsg(sockfd, &UDP_msg[udp_sent], try_to_send, MSG_DONTWAIT);

if ( terminate ) {
  perror("sendmmsg()");
  printf( "Tx-%d,%d,%d,%d\n", udp_sent, udp_2_send, try_to_send, actually_sent );
  pthread_exit(NULL);
}

            if ( actually_sent > 0 ) {
              udp_2_send -= actually_sent;
              udp_sent += actually_sent;
              actually_sent_ever += actually_sent;
              monitor_udp_count += actually_sent;
//printf( "Tx-%d,%d,%d,%d\n", udp_sent, udp_2_send, try_to_send, actually_sent );

            }

          }
//          printf ( "(Sent:%lld)\n", myOSBA->Buff_time );
        } else {                                                                        // If no buffer was held (meaning we didn't find any second that was ready to send)
          usleep(5000);                                                                 // then sleep a bit
        }

      } else {                                                          // There is nothing exciting happening
        usleep(5000);                                                   // Have a nap for 5ms.
      }

    }

    pthread_exit(NULL);                                                 // We fell out of the while loop, so they must want us to terminate
}


//---------------------------------------------------------------------------------------------------------------------------------------------------
// load_port_map - Load RRI to RF_Input mapping from a CSV file.
//
// This file describes how tiles are connected to receivers. Each row represents one of the 16 receivers, and the value in each column is the tile ID
// plugged into the corresponding (external) receiver port.
//---------------------------------------------------------------------------------------------------------------------------------------------------

int load_port_map(char *path, UINT16 *table) {
  // Read the whole input file into a buffer.
  char *data;
  FILE *file;
  size_t sz;
  file = fopen(path, "r");
  if(file == NULL) {
    fprintf(stderr, "Failed to open %s", path);
    return 1;
  }
  fseek(file, 0, SEEK_END);
  sz = ftell(file);
  rewind(file);
  if(sz == -1) {
    fprintf(stderr, "Failed to determine file size: %s", path);
    return 2;
  }
  data = malloc(sz+1);
  data[sz] = '\n';                                     // Simplifies parsing slightly
  if(fread(data, 1, sz, file) != sz) {
    fprintf(stderr, "Failed reading %s - unexpected data length.", path);
    return 3;
  }
  fclose(file);

  int row = 0, col = 0;                                // Current row and column in input table
  char *sep = ",";                                     // Next expected separator
  char *end = NULL;                                    // Mark where `strtol` stops parsing
  char *tok = strtok(data, sep);                       // Pointer to start of next value in input
  while(row < 16) {
    while(col < 8) {
      int tile = strtol(tok, &end, 10);                // Parse the current token as a number,
      if(end == NULL || *end != '\0') break;           // consuming the whole token, or abort.
      
      int id = tile << 1;                              // Internal IDs use lower bit for polarisation
      int cell = row*16 + port_layout[col];            // Determine logical to physical port mapping
      table[cell] = id + 1;                            // Store the higher source ID first.
      table[cell+1] = id;
      
      if(col == 6)                                     // If we've parsed the second-to-last column,
        sep = "\n";                                    // the next separator to expect will be LF.
      else if(col == 7)                                // If we've parsed the last column, the next
        sep = ",";                                     // separator will be a comma again.
      col++;

      tok = strtok(NULL, sep);                         // Get the next token from the input and
      if(tok == NULL) break;                           // abort the row if we don't find one.
    }
    if(col == 8) col = 0;                              // Wrap to column 0 if we parsed a full row
    else break;                                        // or abort if we didn't.
    row++;
  }
  fprintf(stderr, "Found %d rows.", row);
  int result = !(row == 16);                           // Parsing 16 full rows is a success.
  free(data);
  return result;
}

//---------------------------------------------------------------------------------------------------------------------------------------------------

void sigint_handler(int signo)
{
  printf("\n\nAsked to shut down via SIGINT\n");
  fflush(stdout);
  terminate = TRUE;                             // This is a volatile, file scope variable.  All threads should be watching for this.
}

//---------------------------------------------------------------------------------------------------------------------------------------------------

void sigterm_handler(int signo)
{
  printf("\n\nAsked to shut down via SIGTERM\n");
  fflush(stdout);
  terminate = TRUE;                             // This is a volatile, file scope variable.  All threads should be watching for this.
}

//---------------------------------------------------------------------------------------------------------------------------------------------------

void sigusr1_handler(int signo)
{
  printf("\n\nSomeone sent a sigusr1 signal to me.  Will attempt EDT ring buffer reset\n");
  fflush(stdout);
  kick_edt = TRUE;				// Request that we should reset all the EDT card ring buffers
}

//---------------------------------------------------------------------------------------------------------------------------------------------------

void usage(char *err)                           // Bad command line.  Report the supported usage.
{
    printf("%s",err);
    printf("This is edt2udp on xxx.  ver 3.00a Build xxx" );
    printf("\n\n To run:        /home/mwa/edt2udp -c 0 -p /home/mwa/disk3 -o 1114983992\n\n");
    printf(    "                        -c EDT Channel.  Must be 0, or 1 or 2.\n");
    printf(    "                        -p path to directory where the observations live.\n");
    printf(    "                        -o initial observation id.\n");
    printf(    "                        -v verbose reporting mode.\n");
    printf(    "                        -s start capture GPS time.\n");
    printf(    "                        -m maximum number of capture files to save.\n");
    printf(    "                        -b number of EDT card buffers (default=12).\n");
    printf(    "                        -d size EDT card DMA buffers in MB (default=12).\n");
    fflush(stdout);
}

// ------------------------ Start of world -------------------------

int main(int argc, char **argv)
{
    int prog_build = BUILD;                     // Build number.  Remember to update each build revision!
    int loop,loop1,loop2;                       // General purpose.  Usage changes in context
    terminate = FALSE;

//---------------- Trap signals from outside the program ------------------------

    signal(SIGINT, sigint_handler);                     // Tell the OS that we want to trap SIGINT calls
    signal(SIGTERM, sigterm_handler);                   // Tell the OS that we want to trap SIGTERM calls
    signal(SIGUSR1, sigusr1_handler);                   // Tell the OS that we want to trap SIGUSR1 calls

//---------------- Check for leap seconds in GPS time offset ------------------------
/*
    struct timespec check_leap_secs;                            // We need to look at the current time to see if the leap second has occurred.  That takes memory space to store it.
    clock_gettime( CLOCK_REALTIME, &check_leap_secs);           // Ask the OS what the wall clock time is
    if ( ((INT64)check_leap_secs.tv_sec) >= 1483228799 ) GPS_offset = 315964782;        // If it's after leap second occurred then GPS offset is different.  NB check_leap_secs is in Linux epoch NOT GPS epoch time
*/
    printf( "Leap second offset is currently %d\n", GPS_offset );
    fflush(stdout);

//---------------- Parse command line parameters ------------------------

    while (argc > 1 && argv[1][0] == '-') {
      switch (argv[1][1]) {

        case 'c':
          ++argv;
          --argc;

          if (argc < 2)
            usage("Error: option 'c' requires a numeric argument between 0 and 2 inclusive\n");

          if ((argv[1][0] >= '0') && (argv[1][0] <= '2')) {
            edt_channel = atoi(argv[1]);
          } else {
            usage("Error: option 'c' requires a numeric argument between 0 and 2 inclusive\n");
          }
          break;

        case 'u':
          ++argv ;
          --argc ;
          edt_unit = atoi(argv[1]);
          break;

        case 'v':
          verbose = TRUE;
          break ;

        case 'p':
          ++argv ;
          --argc ;
          my_path = argv[1];
          break ;

        case 'o':
          ++argv ;
          --argc ;
          current_obs_id = strtoll(argv[1],0,0);
          break;

        case 's':
          ++argv ;
          --argc ;
          start_capture_time = strtoll(argv[1],0,0);
          break;

        case 'm':
          ++argv ;
          --argc ;
          max_files = atoi(argv[1]);
          break;

        case 'b':
          ++argv ;
          --argc ;
          edtbufs = atoi(argv[1]);
          break;

        case 'd':
          ++argv ;
          --argc ;
          edtbufsize = atoi(argv[1]);
          break;

        default:
          usage("unknown option") ;
          return(0);                            // Exit

      }
      --argc ;
      ++argv ;
    }

    if (argc > 1) {                             // There is/are at least one command line option we don't understand
      usage("");                                // Print the available options
      return(0);                                // Exit the program
    }

// ------------------------ Set up configuration data for this instance of the program -------------------------

    char hostname[300];                                 // Long enough to fit a 255 byte host name.  Probably it will only be short, but -hey- it's just a few bytes

    if ( gethostname( hostname, sizeof hostname ) == -1 ) strcpy( hostname, "unknown" );        // if we can't read a hostname, set a default

    printf("Startup edt2udp on %s.  ver 3.00a Build %d\n", hostname, prog_build);
    fflush(stdout);

    read_config( hostname, edt_unit, edt_channel, &conf );                                      // Populate the configuration info based on hostname, edt_unit and edt_channel

    if ( conf.edt2udp_id == 0 ) {                                                               // If the lookup returned an id of 0, we don't have enough information to continue
      printf("Hostname not found in configuration\n");
      fflush(stdout);
      return(0);                                                                                // Abort!
    }

// ------------------------ Set up data for CPU affinity so that we can control which socket & core we run on -------------------------

//    pthread_t my_thread;                      // I need to look up my own TID / LWP
//    my_thread = pthread_self();                       // So what's my TID / LWP?

    CPU_ZERO(&physical_id_0);                   // Zero out the initial set
    CPU_ZERO(&physical_id_1);                   // This one too
    CPU_SET( 0, &physical_id_0);                // CPU  0 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET( 1, &physical_id_0);                // CPU  1 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET( 2, &physical_id_0);                // CPU  2 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET( 3, &physical_id_0);                // CPU  3 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET( 4, &physical_id_0);                // CPU  4 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET( 5, &physical_id_0);                // CPU  5 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET( 6, &physical_id_0);                // CPU  6 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET( 7, &physical_id_0);                // CPU  7 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET( 8, &physical_id_1);                // CPU  8 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET( 9, &physical_id_1);                // CPU  9 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(10, &physical_id_1);                // CPU 10 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(11, &physical_id_1);                // CPU 11 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(12, &physical_id_1);                // CPU 12 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(13, &physical_id_1);                // CPU 13 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(14, &physical_id_1);                // CPU 14 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(15, &physical_id_1);                // CPU 15 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(16, &physical_id_0);                // CPU 16 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET(17, &physical_id_0);                // CPU 17 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET(18, &physical_id_0);                // CPU 18 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET(19, &physical_id_0);                // CPU 19 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET(20, &physical_id_0);                // CPU 20 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET(21, &physical_id_0);                // CPU 21 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET(22, &physical_id_0);                // CPU 22 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET(23, &physical_id_0);                // CPU 23 is on physical_id 0 (from /proc/cpuinfo)
    CPU_SET(24, &physical_id_1);                // CPU 24 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(25, &physical_id_1);                // CPU 25 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(26, &physical_id_1);                // CPU 26 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(27, &physical_id_1);                // CPU 27 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(28, &physical_id_1);                // CPU 28 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(29, &physical_id_1);                // CPU 29 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(30, &physical_id_1);                // CPU 30 is on physical_id 1 (from /proc/cpuinfo)
    CPU_SET(31, &physical_id_1);                // CPU 31 is on physical_id 1 (from /proc/cpuinfo)

/*
    if (edt_channel==0)
      printf("Set process cpu affinity to NUMA node0 returned %d\n",pthread_setaffinity_np(my_thread, sizeof(cpu_set_t), &physical_id_0));
    else
      printf("Set process cpu affinity to NUMA node1 returned %d\n",pthread_setaffinity_np(my_thread, sizeof(cpu_set_t), &physical_id_1));
*/

//---------------- Create mutex for main array ------------------------

    if (pthread_mutex_init(&buff_array_mx, NULL) != 0) {
      printf("\n buff_array_mx init failed\n"); return 1; }

//---------------- Create an initial pool of buffers ------------------------

    for (loop=0; loop<4; loop++) {

      if ( posix_memalign((void **)&OneSecBuffArray[loop].Buff_ptr,4096,OneSecBuff_Size+6) != 0 ) OneSecBuffArray[loop].Buff_ptr = NULL;

      OneSecBuffArray[loop].Converted2udp = 2;                                       // Set these initial values to say that we've finished converting this (junk) block
      OneSecBuffArray[loop].Sent2nic = TRUE;                                            // Set these initial values to say that we've finished sending this (junk) block

      OneSecBuffArray[loop].Neededby = 0;
      OneSecBuffArray[loop].Buff_next = -1;
      OneSecBuffArray[loop].Buff_prev = -1;
      OneSecBuffArray[loop].Buff_locks = 0;
    }

    FlipBuffArray[0].OneSecBuff_ndx = 0;                                                // Point the 0th flip buffer to the 0th array buffer
    FlipBuffArray[0].Buff_ptr = OneSecBuffArray[0].Buff_ptr;

    if (pthread_mutex_init(&FlipBuffArray[0].Buff_mx, NULL) != 0) {                     // Initialise the Mutex that will mediate access
      printf("\n Flip[0] mutex init failed\n");
      fflush(stdout);
      return 1;
    }

    FlipBuffArray[1].OneSecBuff_ndx = 1;                                                // Do the same for the other flip buffer
    FlipBuffArray[1].Buff_ptr = OneSecBuffArray[1].Buff_ptr;

    if (pthread_mutex_init(&FlipBuffArray[1].Buff_mx, NULL) != 0) {
      printf("\n Flip[1] mutex init failed\n");
      fflush(stdout);
      return 1;
    }

    OneSecBuffArray[2].Buff_next = 3;                                                   // Create the very small linked list forward
    OneSecBuffArray[3].Buff_prev = 2;                                                   // and the linked list backwards

    OneSecBuff_inuse = 4;                       // Number of buffers allocated and managed
    OneSecBuff_first = 2;                       // Index into metadata array for earliest chronological block
    OneSecBuff_last = 3;                        // Index into metadata array for most recent chronological block

// ------------------------ Create the buffers for the udp packets threads -------------------------
// Each second requires room for UDP_PER_MC (80000) packets of type mwa_udp_packet
// We're looping UDP_BUFS (16) times to malloc up a total of 16 seconds.
// The udp packets *inside* a second are contiguous but the different seconds aren't (ie don't need to be)
// -------------------------------------------------------------------------------------------------

    for ( loop = 0; loop < UDP_BUFS; loop++ ) {                                         // One loop for each seconds worth of udp buffers

      if ( posix_memalign((void **)&udpbuff[loop], 4096, ( sizeof(struct mwa_udp_packet) * UDP_PER_MC ) ) != 0 ) {      // malloc up enough for 80000 udp packets for this second
        udpbuff[loop] = NULL;
        printf( "\nudp buffer init failed on loop=%d\n", loop );                        // Fatal, so die early
        fflush(stdout);
        return(0);
      }

    }

//---------------- Create a pool of observation metabin records and populate them ------------------------
/*
    UINT16 rri2rf_input[256] = {                                                                // RRI to rf_input LONG BASELINE *with* RFIpole
        4009,4008,4007,4006,4005,4004,4003,4002,4017,4016,4015,4014,4013,4012,4011,4010,
        269,268,267,266,265,264,263,262,277,276,275,274,273,272,271,270,
        4089,4088,4087,4086,4085,4084,4083,4082,4097,4096,4095,4094,4093,4092,4091,4090,
        4105,4104,4103,4102,4101,4100,4099,4098,4113,4112,4111,4110,4109,4108,4107,4106,
        109,108,107,106,105,104,103,102,117,116,115,114,113,112,111,110,
        289,288,287,286,285,284,283,282,297,296,295,294,293,292,291,290,
        149,148,147,146,145,144,143,142,157,156,155,154,153,152,151,150,
        4025,4024,4023,4022,4021,4020,4019,4018,4033,4032,4031,4030,4029,4028,4027,4026,
        4057,4056,4055,4054,4053,4052,4051,4050,4065,4064,4063,4062,4061,4060,4059,4058,
        209,208,1999,1998,205,204,203,202,217,216,215,214,213,212,211,210,
        229,228,227,226,225,224,223,222,237,236,235,234,233,232,231,230,
        249,248,247,246,245,244,243,242,257,256,255,254,253,252,251,250,
        4073,4072,4071,4070,4069,4068,4067,4066,4081,4080,4079,4078,4077,4076,4075,4074,
        4041,4040,4039,4038,4037,4036,4035,4034,4049,4048,4047,4046,4045,4044,4043,4042,
        309,308,307,306,305,304,303,302,317,316,315,314,313,312,311,310,
        329,328,327,326,325,324,323,322,337,336,335,334,333,332,331,330
    };
*/

    UINT16 rri2rf_input[256] = {                                                                // RRI to rf_input LONG BASELINE *without* RFIpole
        4009,4008,4007,4006,4005,4004,4003,4002,4017,4016,4015,4014,4013,4012,4011,4010,
        269,268,267,266,265,264,263,262,277,276,275,274,273,272,271,270,
        4089,4088,4087,4086,4085,4084,4083,4082,4097,4096,4095,4094,4093,4092,4091,4090,
        69,68,67,66,65,64,63,62,77,76,75,74,73,72,71,70,
        109,108,107,106,105,104,103,102,117,116,115,114,113,112,111,110,
        289,288,287,286,285,284,283,282,297,296,295,294,293,292,291,290,
        149,148,147,146,145,144,143,142,157,156,155,154,153,152,151,150,
        4025,4024,4023,4022,4021,4020,4019,4018,4033,4032,4031,4030,4029,4028,4027,4026,
        4057,4056,4055,4054,4053,4052,4051,4050,4065,4064,4063,4062,4061,4060,4059,4058,
        209,208,207,206,205,204,203,202,217,216,215,214,213,212,211,210,
        229,228,227,226,225,224,223,222,237,236,235,234,233,232,231,230,
        249,248,247,246,245,244,243,242,257,256,255,254,253,252,251,250,
        4073,4072,4071,4070,4069,4068,4067,4066,4081,4080,4079,4078,4077,4076,4075,4074,
        4041,4040,4039,4038,4037,4036,4035,4034,4049,4048,4047,4046,4045,4044,4043,4042,
        309,308,307,306,305,304,303,302,317,316,315,314,313,312,311,310,
        329,328,327,326,325,324,323,322,337,336,335,334,333,332,331,330
    };
    if(load_port_map("/vulcan/mwax_config/tile_ids.txt", rri2rf_input) != 0) {
      fprintf(stderr, "Failed to load port configuration data.");
      exit(1);
    }
    for(int i=0; i<256; i++) {
      fprintf(stderr, "%d, ", rri2rf_input[i]);
    }

/*
    UINT16 rri2rf_input[256] = {                                                                // RRI to rf_input SHORT BASELINE
	29,28,27,26,25,24,23,22,37,36,35,34,33,32,31,30,
	69,68,67,66,65,64,63,62,77,76,75,74,73,72,71,70,
	2041,2040,2039,2038,2037,2036,2035,2034,2049,2048,2047,2046,2045,2044,2043,2042,
	2057,2056,2055,2054,2053,2052,2051,2050,2065,2064,2063,2062,2061,2060,2059,2058,
	2121,2120,2119,2118,2117,2116,2115,2114,2129,2128,2127,2126,2125,2124,2123,2122,
	2105,2104,2103,2102,2101,2100,2099,2098,2113,2112,2111,2110,2109,2108,2107,2106,
	2089,2088,2087,2086,2085,2084,2083,2082,2097,2096,2095,2094,2093,2092,2091,2090,
	169,168,167,166,165,164,163,162,177,176,175,174,173,172,171,170,
	189,188,187,186,185,184,183,182,197,196,195,194,193,192,191,190,
	2137,2136,2135,2134,2133,2132,2131,2130,2145,2144,2143,2142,2141,2140,2139,2138,
	129,128,127,126,125,124,123,122,137,136,135,134,133,132,131,130,
	89,88,87,86,85,84,83,82,97,96,55,54,93,92,91,90,
	2009,2008,2007,2006,2005,2004,2003,2002,2017,2016,2015,2014,2013,2012,2011,2010,
	49,48,47,46,45,44,43,42,57,56,95,94,53,52,51,50,
	2025,2024,2023,2022,2021,2020,2019,2018,2033,2032,2031,2030,2029,2028,2027,2026,
	2073,2072,2071,2070,2069,2068,2067,2066,2081,2080,2079,2078,2077,2076,2075,2074
    };
*/

    for ( loop = 0; loop < MAX_OBS_IDS; loop++ ) {                                      // One loop for each observation we store the metadata for

      obs_meta[loop].obs_id =   1000000000LL;
      obs_meta[loop].last_GPS = 1000000000LL;
      obs_meta[loop].obs_mode = 1;

      for ( loop1 = 0 ; loop1 < 16 ; loop1++ ) {
        for ( loop2 = 0 ; loop2 < 16 ; loop2++ ) {
          obs_meta[loop].rf_input_map[loop1][loop2] = rri2rf_input[loop1<<4 | loop2];   // From the metabin, a list of rf_input "tile_id"s sorted by receiver number followed by the order in which they appear in that receivers RRI packets
//          obs_meta[loop].rf_input_map[loop1][loop2] = loop1<<4 | loop2;               // From the metabin, a list of rf_input "tile_id"s sorted by receiver number followed by the order in which they appear in that receivers RRI packets
        }
      }

      for ( loop1 = 0 ; loop1 < 3 ; loop1++ ) {
        for ( loop2 = 0 ; loop2 < 8 ; loop2++ ) {
//          obs_meta[loop].sky_freq_map[loop1][loop2] = 65+loop1*8+loop2;       // From the metabin, a list of sky frequencies [0 to 255 inclusive] sorted by which of the three fibres from a receiver they are on followed by the order in RRI packets
          obs_meta[loop].sky_freq_map[loop1][loop2] = loop1*8+loop2+1;          // 1 to 24 to match the gpubox order.  Kludge for when not reading the metafits.  Real sky channels from 1 to 24 are never used anyway.
          obs_meta[loop].multicast_dest_map[loop1][loop2] = loop1*8+loop2+1;    // From the metabin, the complete list of all multicast streams (24) but sorted by which of the three fibres from a receiver they are on followed by the order in RRI packets
        }
      }

      obs_meta[0].last_GPS = 10000000000LL;
    }

// ------------------------ Create the worker threads -------------------------

    pthread_t edt2flip_pt;                      // See thread list above for details on the following threads
    pthread_t flip2buff_pt;
    pthread_t buff2udp_pt;
    pthread_t buff2udp2_pt;
    pthread_t udp2nic_pt;

    pthread_create(&edt2flip_pt,NULL,edt2flip,NULL);
    pthread_create(&flip2buff_pt,NULL,flip2buff,NULL);
    pthread_create(&buff2udp_pt,NULL,buff2udp,NULL);
    pthread_create(&buff2udp2_pt,NULL,buff2udp,NULL);
    pthread_create(&udp2nic_pt,NULL,udp2nic,NULL);

    while(!terminate) sleep(1);                 // The master thread currently does nothing! Zip! Nada!  What a waste eh?

    pthread_join(edt2flip_pt,NULL);
    printf("Joined edt2flip\n");
    fflush(stdout);

    pthread_join(flip2buff_pt,NULL);
    printf("Joined flip2buff\n");
    fflush(stdout);

    pthread_join(buff2udp_pt,NULL);
    printf("Joined buff2udp\n");
    fflush(stdout);

    pthread_join(buff2udp2_pt,NULL);
    printf("Joined buff2udp2\n");
    fflush(stdout);

    pthread_join(udp2nic_pt,NULL);
    printf("Joined udp2nicp\n");
    fflush(stdout);

    pthread_mutex_destroy( &buff_array_mx );                            // We've finished so free up the resources
    pthread_mutex_destroy( &FlipBuffArray[0].Buff_mx );
    pthread_mutex_destroy( &FlipBuffArray[1].Buff_mx );

/*  WIP!!! free up the malloced buffers */

    printf("Done\n");
    fflush(stdout);

    return(0);
}
