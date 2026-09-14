module top (
    input  n1_in,
    input  n3_in,
    input  n4_in,
    input  n_clk,
    output n4_out
);

// Internal wires
wire n1_out;
wire n2_out;
wire n3_out;

// Gates
not g1 (
    n1_out,
    n1_in
);

nand g2(
    n2_out,
    n1_out,
    n3_in
);

or
g3
(
    n3_out,
    n2_out,
    n4_in
);

dff g4 (
    .RN(1'b1),
    .SN(1'b1),
    .CK(n_clk),
    .D(n3_out),
    .Q(n4_out)
);

endmodule