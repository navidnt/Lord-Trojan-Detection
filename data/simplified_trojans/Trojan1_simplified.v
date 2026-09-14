module Trojan1 ( clk, rst, r1, trigger );
input w_0, w_1, w_2;output w_3;wire w_4, w_5, w_6, w_7, w_8, w_9, w_10, w_11, w_12, w_13, w_14, w_15, w_16, w_17, w_18, w_19, w_20, w_21, w_22, w_23, w_24, w_25, w_26, w_27, w_28, w_29, w_30;wire    [2:0] w_31;

dff g_1 ( .RN(1'b1), .SN(1'b1), .CK(w_0), .D(w_30), .Q(w_31[0]) );
dff g_2 ( .RN(1'b1), .SN(1'b1), .CK(w_0), .D(w_29), .Q(w_31[1]) );
dff g_3 ( .RN(1'b1), .SN(1'b1), .CK(w_0), .D(w_28), .Q(w_31[2]) );
dff g_4 ( .RN(1'b1), .SN(1'b1), .CK(w_0), .D(w_27), .Q(w_3) );
not g_5 ( w_4, w_19 );
not g_6 ( w_5, w_1 );
not g_7 ( w_6, w_24 );
not g_8 ( w_7, w_17 );
not g_9 ( w_8, w_15 );
not g_10 ( w_9, w_26 );
not g_11 ( w_10, w_2 );
not g_12 ( w_11, w_31[1] );
not g_13 ( w_12, w_31[2] );
or g_14 ( w_27, w_13, w_5 );
and g_15 ( w_13, w_14, w_8 );
and g_16 ( w_15, w_16, w_3 );
or g_17 ( w_14, w_3, w_16 );
or g_18 ( w_16, w_17, w_12 );
and g_19 ( w_28, w_18, w_4 );
and g_20 ( w_19, w_20, w_7 );
or g_21 ( w_18, w_7, w_20 );
or g_22 ( w_20, w_5, w_12 );
or g_23 ( w_29, w_21, w_7 );
or g_24 ( w_17, w_10, w_22 );
or g_25 ( w_22, w_9, w_11 );
and g_26 ( w_21, w_23, w_24 );
or g_27 ( w_23, w_5, w_11 );
or g_28 ( w_30, w_25, w_6 );
or g_29 ( w_24, w_9, w_10 );
and g_30 ( w_25, w_9, w_10 );
and g_31 ( w_26, w_1, w_31[0] );
endmodule

