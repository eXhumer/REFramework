#pragma once

#include <array>

#include "vr/D3D12Component.hpp"
#include "Mod.hpp"

namespace sdk {
namespace renderer {
class RenderLayer;

namespace layer {
class Scene;
}
}
}

class TemporalUpscaler : public Mod {
public:
    static std::shared_ptr<TemporalUpscaler>& get();

    std::string_view get_name() const { return "TemporalUpscaler"; }

    std::optional<std::string> on_initialize() override;

    void on_config_load(const utility::Config& cfg) override;
    void on_config_save(utility::Config& cfg) override;

    void on_draw_ui() override;
    void on_early_present() override; // early because it needs to run before VR.
    void on_post_present() override;
    void on_device_reset() override;

    void on_pre_application_entry(void* entry, const char* name, size_t hash) override;
    void on_application_entry(void* entry, const char* name, size_t hash) override;

    void on_view_get_size(REManagedObject* scene_view, float* result) override;
    void on_camera_get_projection_matrix(REManagedObject* camera, Matrix4x4f* result) override;

    void on_scene_layer_update(sdk::renderer::layer::Scene* scene_layer, void* render_context) override;
    
    bool on_pre_output_layer_draw(sdk::renderer::layer::Output* layer, void* render_context) override;
    bool on_pre_output_layer_update(sdk::renderer::layer::Output* layer, void* render_context) override;

    bool ready() const {
        return m_initialized && m_backend_loaded && m_enabled && !m_wants_reinitialize;
    }

    uint32_t get_evaluate_id(uint32_t counter) {
        return (counter % 2) + 1;
    }

    template<typename T>
    T* get_upscaled_texture(int32_t index) {
        if (index < 0 || index > m_upscaled_textures.size()) {
            return nullptr;
        }

        return (T*)m_upscaled_textures[index];
    }

    enum PDGraphicsAPI {
        D3D11,
        D3D12,
        VULKAN
    };

    enum PDUpscaleType {
        DLSS,
        FSR2,
        XESS
    };

    enum PDPerfQualityLevel {
        Performance,
        Balanced,
        Quality,
        UltraPerformance
    };


private:
    template <typename T> using ComPtr = Microsoft::WRL::ComPtr<T>;

    bool on_first_frame();
    bool init_upscale_features();
    void release_upscale_features();
    void fix_output_layer();
    void update_mirror();

    bool m_first_frame_finished{false};
    bool m_initialized{false};
    bool m_is_d3d12{false};
    bool m_backend_loaded{false};
    bool m_backbuffer_inconsistency{false};
    bool m_enabled{true};
    bool m_upscale{true};
    bool m_rendering{false};
    bool m_set_view{false};
    bool m_jitter{true};
    bool m_sharpness{true};
    bool m_allow_taa{false}; // the engine has its own TAA implementation, it can't be used with the upscaler
    bool m_wants_reinitialize{false};
    bool m_made_mirror{false};

    std::unordered_map<std::string, size_t> m_available_upscale_methods{};
    std::vector<std::string> m_available_upscale_method_names{};
    std::array<uint32_t, 2> m_jitter_indices{0, 0};

    uint32_t m_available_upscale_type{0};
    PDUpscaleType m_upscale_type{PDUpscaleType::FSR2};
    PDPerfQualityLevel m_upscale_quality{PDPerfQualityLevel::Balanced};

    uint32_t m_backbuffer_inconsistency_start{};
    std::array<uint32_t, 2> m_backbuffer_size{};

    std::array<void*, 2> m_upscaled_textures{nullptr, nullptr};

    sdk::renderer::layer::Scene* m_cloned_scene_layer{nullptr};
    sdk::renderer::layer::Output* m_output_layer{nullptr};
    sdk::renderer::layer::Output* m_original_output_layer{nullptr};
    sdk::renderer::layer::Output* m_cloned_output_layer{nullptr};
    sdk::renderer::layer::Output* m_last_output_layer{nullptr};
    sdk::renderer::TargetState* m_last_output_state{nullptr};
    sdk::renderer::ConstantBuffer* m_original_scene_info_buffer{};
    sdk::renderer::ConstantBuffer* m_cloned_scene_info_buffer{};

    sdk::renderer::TargetState* m_new_target_state{nullptr};


    struct EyeState {
        sdk::renderer::layer::Scene* scene_layer{nullptr};
        void* motion_vectors{nullptr};
        void* depth{nullptr};
        void* color{nullptr};
    };

    std::array<EyeState, 2> m_eye_states{};

    int32_t m_displayed_scene{0}; // 0 = original, 1 = cloned

    float m_nearz{0.0f};
    float m_farz{0.0f};
    float m_fov{90.0f};
    float m_sharpness_amount{0.0f};

    float m_jitter_offsets[2][2]{0.0f, 0.0f};
    float m_jitter_scale[2]{2.0f, -2.0f};
    float m_motion_scale[2]{-1.0f, 1.0f};
    float m_jitter_evaluate_scale{1.0f};

    vrmod::D3D12Component::ResourceCopier m_copier{};
    ComPtr<ID3D12Resource> m_old_backbuffer{};

    struct GBuffer {
        std::vector<ComPtr<ID3D12Resource>> textures{};
    };
    
    GBuffer m_real_gbuffer{};

    std::array<ComPtr<ID3D12Resource>, 2> m_prev_motion_vectors_d3d12{};
    std::array<GBuffer, 2> m_prev_g_buffer_d3d12{};
    std::array<std::array<Matrix4x4f, 6>, 2> m_old_projection_matrix{};
    std::array<std::array<Matrix4x4f, 6>, 2> m_old_view_matrix{};

    std::array<std::vector<uint8_t>, 2> m_scene_layer_datas{};
};