
module ALU8(
    input [7:0] A,
    input [7:0] B,
    input [2:0] opcode,
    output reg [7:0] result
);

always @(*) begin
    case (opcode)
        3'b000: result = A + B; // addition
        3'b001: result = A - B; // subtraction
        default: result = 8'b0; // default to 0
    endcase
end

endmodule
