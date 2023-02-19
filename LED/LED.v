module LED (
  input wire clock,
  input wire reset,
  output reg led
);

always @(posedge clock) begin
  if (reset) begin
    led <= 0;
  end else begin
    led <= ~led;
  end
end
endmodule

