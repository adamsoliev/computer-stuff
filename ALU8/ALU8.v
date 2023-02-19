
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
        3'b010: begin           // multiplication
            reg [7:0] temp_result = 8'b0;
            reg [7:0] temp_B = B; 
            for (int i = 0; i < 8; i = i + 1) begin
                if (temp_B[0] == 1) begin
                    temp_result = temp_result + (A << i);
                end
                temp_B = temp_B >> 1;
            end
            result = temp_result;
        end
        3'b011: begin           // division
            if (B == 0) begin
                result = 8'hFF;
            end
            else begin
                result = A / B;
            end
        end
        default: result = 8'b0; // default to 0
    endcase
end

endmodule
