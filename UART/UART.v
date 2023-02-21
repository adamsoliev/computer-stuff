// this is mostly a copy of the below with my comments
// https://github.com/ben-marshall/uart/tree/master/rtl
// =====================================================
module impl_top (
    input clk, // sys clock input
    input sw_0, // slide switches
    input sw_1, // slide switches
    input wire uart_rxd, // receive pin
    output wire uart_txd, // transmit pin
    output wire [7:0] led // led
);

parameter CLK_HZ = 50000000; // 50M
parameter BIT_RATE = 9600; 
parameter PAYLOAD_BITS = 8;

wire [PAYLOAD_BITS-1:0] uart_rx_data;
wire uart_rx_valid;
wire uart_rx_break;

wire uart_tx_busy;
wire [PAYLOAD_BITS-1:0] uart_tx_data;
wire uart_tx_en;

reg [PAYLOAD_BITS-1:0] led_reg;
assign led = led_reg;

// ---------------
assign uart_tx_data = uart_rx_data;
assign uart_tx_en = uart_rx_valid;

always @(posedge clk) begin
    if (!sw_0) begin
        led_reg <= 8'hF0;
    end else if (uart_rx_valid) begin
        led_reg <= uart_rx_data[7:0];
    end
end

// -----------------

// UART RX
uart_rx #(
    .BIT_RATE(BIT_RATE),
    .PAYLOAD_BITS(PAYLOAD_BITS),
    .CLK_HZ(CLK_HZ)
) i_uart_rx(
    .clk(clk),
    .resetn(sw_0), // asynch active low reset
    .uart_rxd(uart_rxd), // receive pin
    .uart_rx_en(1'b1), // receive enabled
    .uart_rx_break(uart_rx_break), // did we get a break msg?
    .uart_rx_valid(uart_rx_valid), // valid data received and available
    .uart_rx_data(uart_rx_data) // received data
);

// UART TX
uart_tx #(
    .BIT_RATE(BIT_RATE),
    .PAYLOAD_BITS(PAYLOAD_BITS),
    .CLK_HZ(CLK_HZ)
) i_uart_tx(
    .clk(clk),
    .resetn(sw_0), // asynch active low reset
    .uart_txd(uart_txd), // receive pin
    .uart_tx_en(uart_tx_en),
    .uart_tx_busy(uart_tx_busy),
    .uart_tx_data(uart_tx_data)
);
endmodule

// =====================================================

module uart_rx(
    input wire clk, // sys clock
    input wire resetn, // asynch active low reset
    input wire uart_rxd, // receive pin
    input wire uart_rx_en, // enable/disable the module 
    output wire uart_rx_break, // did we get a break msg?
    output wire uart_rx_valid, // valid data received and available
    output reg [PAYLOAD_BITS-1:0] uart_rx_data // output bus that has received data
);

// External parameters
// --------------------
// Input bit rate of the UART line
parameter BIT_RATE = 9600; // bits/sec
localparam BIT_P = 1_000_000_000 * 1/BIT_RATE; // how long it takes to send a bit in nanoseconds

// Clock freq in hertz
parameter CLK_HZ = 50_000_000;
localparam CLK_P = 1_000_000_000 * 1/CLK_HZ; // how long each click cycles takes in nanosecods

// Number of data bits received per UART packet
parameter PAYLOAD_BITS = 8;

// Number of stop bits indicating the end of packet
parameter STOP_BITS = 1;

// Internal parameters
// --------------------
// Number of clock cycles per uart bit
localparam CYCLES_PER_BIT = BIT_P / CLK_P;

// Size of the registers which store sample counts and bit durations
localparam COUNT_REG_LEN = 1 + $clog2(CYCLES_PER_BIT);

// Internal registers 
// --------------------
reg rxd_reg;
reg rxd_reg_0;

// Storage for the received serial data
reg [PAYLOAD_BITS-1:0] received_data;

// Counter for the number of cycles over a packet bit.
reg [COUNT_REG_LEN-1:0] cycle_counter;

// Counter for the nubmer of received bits of the packet
reg [3:0] bit_counter;

// Sample of the UART input line whether we are in the middle of a bit frame
reg bit_sample;

// Current and next states of the internal FSM (finite state machine)
reg [2:0] fsm_state;
reg [2:0] n_fsm_state;

localparam FSM_IDLE = 0;
localparam FSM_START = 1;
localparam FSM_RECV = 2;
localparam FSM_STOP = 3;


// Output assignment
// break when rx is valid and received_data is all 0s (break msg)
assign uart_rx_break = uart_rx_valid && ~|received_data;
// valid if done cur state is STOP and next is idle (done receiving and ready for more)
assign uart_rx_valid = fsm_state == FSM_STOP && n_fsm_state == FSM_IDLE;

always @(posedge clk) begin
    if (!resetn) begin
        // at reset, set to all 0s
        uart_rx_data <= {PAYLOAD_BITS{1'b0}};
    end else if (fsm_state == FSM_STOP) begin
        // done receiving, write data to output register
        uart_rx_data <= received_data;
    end
end

// FSM next state selection
wire next_bit = cycle_counter == CYCLES_PER_BIT || fsm_state == FSM_STOP && cycle_counter == CYCLES_PER_BIT/2;
wire payload_done = bit_counter == PAYLOAD_BITS;

// IDLE => START => RECV => STOP => IDLE => ...
// Handle picking the next state
always @(*) begin: _p_n_fsm_state
    case(fsm_state)
        FSM_IDLE: n_fsm_state = rxd_reg ? FSM_IDLE : FSM_START;
        FSM_START: n_fsm_state = next_bit ? FSM_RECV : FSM_START;
        FSM_RECV: n_fsm_state = payload_done ? FSM_STOP : FSM_RECV;
        FSM_STOP: n_fsm_state = next_bit ? FSM_IDLE : FSM_STOP;
        default: n_fsm_state = FSM_IDLE;
    endcase
end

// Internal register setting and re-setting

// Handle updates to the received data register
integer i = 0;
always @(posedge clk) begin: p_received_data
    if (!resetn) begin
        received_data <= {PAYLOAD_BITS{1'b0}};
    end else if (fsm_state == FSM_IDLE) begin
        received_data <= {PAYLOAD_BITS{1'b0}};
    end else if (fsm_state == FSM_RECV && next_bit) begin
        // assign 'new bit' to the most significant bit
        received_data[PAYLOAD_BITS-1] <= bit_sample;
        // shift down other bits by one 
        for (i = PAYLOAD_BITS-2; i >= 0; i = i -1) begin
            received_data[i] <= received_data[i+1];
        end
    end
end

// Increment the bit counter when receiving
always @(posedge clk) begin: p_bit_counter
    if (!resetn) begin
        bit_counter <= 4'b0;
    end else if (fsm_state != FSM_RECV) begin
        bit_counter <= {COUNT_REG_LEN{1'b0}};
    end else if (fsm_state == FSM_RECV && next_bit) begin
        bit_counter <= bit_counter + 1'b1;
    end
end

// Sample the received bit when in the middle of a bit frame
always @(posedge clk) begin: p_bit_sample
    if (!resetn) begin
        bit_sample <= 1'b0;
    end else if (cycle_counter == CYCLES_PER_BIT/2) begin
        bit_sample <= rxd_reg;
    end
end

// Increment the cycle counter when receiving
always @(posedge clk) begin: p_cycle_counter
    if (!resetn) begin
        cycle_counter <= {COUNT_REG_LEN{1'b0}};
    end else if (next_bit) begin
        cycle_counter <= {COUNT_REG_LEN{1'b0}};
    end else if (fsm_state == FSM_START || fsm_state == FSM_RECV || fsm_state == FSM_STOP) begin
        cycle_counter <= cycle_counter + 1'b1;
    end
end

// Progress the next FSM state
always @(posedge clk) begin: p_n_fsm_state
    if (!resetn) begin
        fsm_state <= FSM_IDLE;
    end else begin
        fsm_state <= n_fsm_state;
    end
end

// Update the internal value of the rxd_reg
always @(posedge clk) begin: p_rxd_reg
    if (!resetn) begin
        rxd_reg <= 1'b1;
        rxd_reg_0 <= 1'b1;
    end else if (uart_rx_en) begin
        // update rxd_reg with a delay (rxd_reg_0) when uart_rx_en is on
        rxd_reg <= rxd_reg_0;
        rxd_reg_0 <= uart_rxd;
    end
end
endmodule


module uart_tx(
    input wire clk, // sys clock
    input wire resetn, // asynch active low reset
    output wire uart_txd, // transmit pin
    output wire uart_tx_busy, // module busy sending prev item
    input wire uart_tx_en, // data available to be sent
    input wire [PAYLOAD_BITS-1:0] uart_tx_data // data to be sent
);

// External parameters
// Input bit rate of the UART line
parameter BIT_RATE = 9600; // bits/sec
localparam BIT_P = 1_000_000_000 * 1/BIT_RATE; // nanoseconds

// Clock freq in hertz
parameter CLK_HZ = 50_000_000;
localparam CLK_P = 1_000_000_000 * 1/CLK_HZ; // nanoseconds

// Number of data bits received per UART packet
parameter PAYLOAD_BITS = 8;

// Number of stop bits indicating the end of a packet
parameter STOP_BITS = 1;

// ---------------------------
// Internal parameters

// Number of clock cycles per uart bit
localparam CYCLES_PER_BIT = BIT_P / CLK_P;

// Size of the registers which store sample counts and bit durations
localparam COUNT_REG_LEN = 1 + $clog2(CYCLES_PER_BIT);

// Internal registers

// Internally latched value of the uart_txd line
reg txd_reg;

// Storage for the serial data to be sent
reg [PAYLOAD_BITS-1:0] data_to_send;

// Counter for the number of cycles over a packet bit
reg [COUNT_REG_LEN-1:0] cycle_counter;

// Counter for the number of sent bits of the packet
reg [3:0] bit_counter;

reg [2:0] fsm_state;
reg [2:0] n_fsm_state;


localparam FSM_IDLE = 0;
localparam FSM_START = 1;
localparam FSM_SEND = 2;
localparam FSM_STOP = 3;

// --------------------------------------------------------------------------- 
// FSM next state selection.
// 

assign uart_tx_busy = fsm_state != FSM_IDLE;
assign uart_txd     = txd_reg;

wire next_bit     = cycle_counter == CYCLES_PER_BIT;
wire payload_done = bit_counter   == PAYLOAD_BITS  ;
wire stop_done    = bit_counter   == STOP_BITS && fsm_state == FSM_STOP;

//
// Handle picking the next state.
always @(*) begin : p_n_fsm_state
    case(fsm_state)
        FSM_IDLE : n_fsm_state = uart_tx_en   ? FSM_START: FSM_IDLE ;
        FSM_START: n_fsm_state = next_bit     ? FSM_SEND : FSM_START;
        FSM_SEND : n_fsm_state = payload_done ? FSM_STOP : FSM_SEND ;
        FSM_STOP : n_fsm_state = stop_done    ? FSM_IDLE : FSM_STOP ;
        default  : n_fsm_state = FSM_IDLE;
    endcase
end

// --------------------------------------------------------------------------- 
// Internal register setting and re-setting.
// 

//
// Handle updates to the sent data register.
integer i = 0;
always @(posedge clk) begin : p_data_to_send
    if(!resetn) begin
        data_to_send <= {PAYLOAD_BITS{1'b0}};
    end else if(fsm_state == FSM_IDLE && uart_tx_en) begin
        data_to_send <= uart_tx_data;
    end else if(fsm_state       == FSM_SEND       && next_bit ) begin
        for ( i = PAYLOAD_BITS-2; i >= 0; i = i - 1) begin
            data_to_send[i] <= data_to_send[i+1];
        end
    end
end


//
// Increments the bit counter each time a new bit frame is sent.
always @(posedge clk) begin : p_bit_counter
    if(!resetn) begin
        bit_counter <= 4'b0;
    end else if(fsm_state != FSM_SEND && fsm_state != FSM_STOP) begin
        bit_counter <= {COUNT_REG_LEN{1'b0}};
    end else if(fsm_state == FSM_SEND && n_fsm_state == FSM_STOP) begin
        bit_counter <= {COUNT_REG_LEN{1'b0}};
    end else if(fsm_state == FSM_STOP&& next_bit) begin
        bit_counter <= bit_counter + 1'b1;
    end else if(fsm_state == FSM_SEND && next_bit) begin
        bit_counter <= bit_counter + 1'b1;
    end
end


//
// Increments the cycle counter when sending.
always @(posedge clk) begin : p_cycle_counter
    if(!resetn) begin
        cycle_counter <= {COUNT_REG_LEN{1'b0}};
    end else if(next_bit) begin
        cycle_counter <= {COUNT_REG_LEN{1'b0}};
    end else if(fsm_state == FSM_START || 
                fsm_state == FSM_SEND  || 
                fsm_state == FSM_STOP   ) begin
        cycle_counter <= cycle_counter + 1'b1;
    end
end


//
// Progresses the next FSM state.
always @(posedge clk) begin : p_fsm_state
    if(!resetn) begin
        fsm_state <= FSM_IDLE;
    end else begin
        fsm_state <= n_fsm_state;
    end
end


//
// Responsible for updating the internal value of the txd_reg.
always @(posedge clk) begin : p_txd_reg
    if(!resetn) begin
        txd_reg <= 1'b1;
    end else if(fsm_state == FSM_IDLE) begin
        txd_reg <= 1'b1;
    end else if(fsm_state == FSM_START) begin
        txd_reg <= 1'b0;
    end else if(fsm_state == FSM_SEND) begin
        txd_reg <= data_to_send[0];
    end else if(fsm_state == FSM_STOP) begin
        txd_reg <= 1'b1;
    end
end

endmodule
