#import "@preview/fletcher:0.4.5" as fletcher: diagram, node, edge

#align(center)[
  #diagram(
    node-stroke: 1pt,
    edge-stroke: 1pt,
    node((0, 0), [`bpf_prog*`], corner-radius: 0pt, name: "start"),
    node((0, 1), [`bpf_check`], corner-radius: 10pt, name: "verifier"),
    node((0, 2), [`bpf_jit_compile`], corner-radius: 10pt, name: "jit"),
    edge(<start>, <verifier>, "->"),
    edge(<verifier>, <jit>, "->"),

    edge((-1,2.5), (1,2.5), "-"),

    node((0, 3), [`bpf_prog*`], corner-radius: 0pt, name: "start2",  fill: red.lighten(60%), stroke: red.lighten(60%)),
    node((0, 4), [Reduced `bpf_check`], corner-radius: 10pt, name: "verifier2",  fill: blue.lighten(60%), stroke: blue.lighten(60%)),
    node((0, 5), [`to_ssa`], corner-radius: 10pt, name: "s3", fill: blue.lighten(60%), stroke: blue.lighten(60%)),
    node((0, 6), [Insert check and profile code], corner-radius: 10pt, name: "s4", fill: blue.lighten(60%), stroke: blue.lighten(60%)),
    node((0, 7), [`reg_alloc`], corner-radius: 10pt, name: "s5", fill: blue.lighten(60%), stroke: blue.lighten(60%)),
    node((0, 8), [`bpf_jit_compile`], corner-radius: 10pt, name: "jit2", fill: gray.lighten(60%), stroke: gray.lighten(60%)),
    node((0, 9), [Collect profile data], corner-radius: 10pt, name: "collect", fill: blue.lighten(60%), stroke: blue.lighten(60%)),
    node((0, 10), [Strict `bpf_check` on hot path], corner-radius: 10pt, name: "check",fill: blue.lighten(60%), stroke: blue.lighten(60%)),
    node((0, 11), [ Remove check code on hot path + Optimization ], corner-radius: 10pt, name: "opt", fill: blue.lighten(60%), stroke: blue.lighten(60%)),
    edge(<start2>, <verifier2>, "->"),
    edge(<verifier2>, <s3>, "->"),
    edge(<s3>, <s4>, "->"),
    edge(<s4>, <s5>, "->"),
    edge(<s5>, <jit2>, "->"),
    edge(<jit2>, <collect>, "->"),
    edge(<collect>, <check>, "->"),
    edge(<check>, <opt>, "->"),
    edge(<opt>,(1,11),(1, 7), <s5>, "->"),
  )
]

