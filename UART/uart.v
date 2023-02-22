/*
   [system A] <= out_data <= R <= rxd === txd <= T <= in_data <= [system B]  
*/

module uart (
    input wire clk,
    input wire rst,
    input reg [7:0] in_data,
    output reg [7:0] out_data,
    input wire rxd,
    output wire txd
);

rx irx(
    .clk(clk),
    .rst(rst),
    .data(out_data),
    .rxd(rxd)
);

tx itx(
    .clk(clk),
    .rst(rst),
    .data(in_data),
    .txd(txd)
);
endmodule

// ------------------------------------------------------------------
// Receiver Module
// ------------------------------------------------------------------
module rx (
    input wire clk,
    input wire rst,
    output wire [7:0] data,
    input wire rxd
);

reg [7:0] data_reg = 0;
reg rxd_reg = 1;

assign data = data_reg;

always @(posedge clk) begin
    if (rst) begin
        data_reg <= 0;
        rxd_reg <= 1;
    end else begin
        rxd_reg <= rxd; // receive a bit 
        data_reg <= {rxd_reg, data_reg[7:1]};
    end
end
endmodule

// ------------------------------------------------------------------
// Transmitter Module
// ------------------------------------------------------------------
module tx (
    input wire clk,
    input wire rst,
    input wire [7:0] data,
    output wire txd
);

reg txd_reg = 1;
reg [7:0] data_reg = 0;
reg [3:0] bit_cnt = 0;

assign txd = txd_reg;

always @(posedge clk) begin
    if (rst) begin
        txd_reg <= 1;
        data_reg <= 0;
        bit_cnt <= 0;
    end else begin
        if (bit_cnt == 0) begin
            data_reg <= data;
            txd_reg <= 0;
        end
        {data_reg, txd_reg} <= {1'b0, data_reg}; // send a bit 
        bit_cnt <= bit_cnt + 1;
    end
end

endmodule