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
    .rx_data(out_data),
    .rxd(rxd)
);

tx itx(
    .clk(clk),
    .rst(rst),
    .tx_data(in_data),
    .txd(txd)
);
endmodule

// ------------------------------------------------------------------
// Receiver Module
// ------------------------------------------------------------------
module rx (
    input wire clk,
    input wire rst,
    output wire [7:0] rx_data,
    input wire rxd
);

reg [7:0] rx_data_reg = 0;
// reg rxd_reg = 1;
// reg [3:0] bit_pos = 0;

assign rx_data = rx_data_reg;

always @(posedge clk) begin
    if (rst) begin
        rx_data_reg <= 0;
        // bit_pos <= 0;
        // rxd_reg <= 1;
    end else begin
    end
end
endmodule

// ------------------------------------------------------------------
// Transmitter Module
// ------------------------------------------------------------------
module tx (
    input wire clk,
    input wire rst,
    input wire [7:0] tx_data,
    output wire txd
);

reg txd_reg;
reg [7:0] tx_data_reg;
reg [3:0] count;

assign txd = txd_reg;

always @(posedge clk) begin
    if (rst) begin
        $display("================ Reset ================");
        count <= 0;
        tx_data_reg <= 0;
        txd_reg <= 0;
    end else begin
        $display("================ Normal ================");
        if (count == 0) begin
            $display("A");
            tx_data_reg <= tx_data;
            count <= count + 1;
        end else if (count < 9) begin
            $display("B");
            tx_data_reg <= {1'b0, tx_data_reg[7:1]};
            txd_reg <= tx_data_reg[0];
            count <= count + 1;
        end else begin
            $display("C");
            count <= 0;
            tx_data_reg <= tx_data;
            txd_reg <= 0;
        end
    end
    $display("[TX] tx_data_reg = %0b, count = %0d, txd_reg = %0b", tx_data_reg, count, txd_reg);
    $display("[TX] tx_data     = %0b", tx_data);

end

endmodule