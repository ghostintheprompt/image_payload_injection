<?php
/**
 * Plugin Name: Image Payload Scanner
 * Plugin URI: https://github.com/moderndime/image-payload-injection
 * Description: Analyzes and sanitizes uploaded images to detect and prevent image payload injection attacks
 * Version: 1.0.0
 * Author: Modern Dime Security Research
 * Author URI: https://moderndime.example.org
 * License: MIT
 * Text Domain: image-payload-scanner
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

// Define constants
define('IPS_VERSION', '1.0.0');
define('IPS_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('IPS_PLUGIN_URL', plugin_dir_url(__FILE__));
define('IPS_API_ENDPOINT', get_option('ips_api_endpoint', 'http://localhost:5000'));

/**
 * Class responsible for the main functionality of the plugin
 */
class Image_Payload_Scanner {
    /**
     * Initialize the plugin
     */
    public function __construct() {
        // Add hooks
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_filter('wp_handle_upload_prefilter', array($this, 'pre_upload_scan'));
        add_filter('attachment_fields_to_edit', array($this, 'add_scan_button_to_media'), 10, 2);
        add_action('wp_ajax_ips_analyze_image', array($this, 'ajax_analyze_image'));
        add_action('wp_ajax_ips_sanitize_image', array($this, 'ajax_sanitize_image'));
        add_action('admin_init', array($this, 'register_settings'));
    }

    /**
     * Register plugin settings
     */
    public function register_settings() {
        register_setting('ips_settings', 'ips_api_endpoint');
        register_setting('ips_settings', 'ips_auto_scan');
        register_setting('ips_settings', 'ips_block_high_risk');
        register_setting('ips_settings', 'ips_sanitize_on_upload');
        register_setting('ips_settings', 'ips_remove_metadata');
    }

    /**
     * Add the admin menu page
     */
    public function add_admin_menu() {
        add_options_page(
            __('Image Payload Scanner Settings', 'image-payload-scanner'),
            __('Image Security', 'image-payload-scanner'),
            'manage_options',
            'image-payload-scanner',
            array($this, 'admin_page')
        );

        add_media_page(
            __('Image Security Scanner', 'image-payload-scanner'),
            __('Security Scanner', 'image-payload-scanner'),
            'upload_files',
            'image-payload-scanner-media',
            array($this, 'media_page')
        );
    }

    /**
     * Admin settings page
     */
    public function admin_page() {
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            return;
        }

        // Save settings if form was submitted
        if (isset($_POST['ips_settings']) && check_admin_referer('ips_settings_nonce')) {
            update_option('ips_api_endpoint', sanitize_url($_POST['ips_api_endpoint']));
            update_option('ips_auto_scan', isset($_POST['ips_auto_scan']) ? 1 : 0);
            update_option('ips_block_high_risk', isset($_POST['ips_block_high_risk']) ? 1 : 0);
            update_option('ips_sanitize_on_upload', isset($_POST['ips_sanitize_on_upload']) ? 1 : 0);
            update_option('ips_remove_metadata', isset($_POST['ips_remove_metadata']) ? 1 : 0);
            
            echo '<div class="notice notice-success is-dismissible"><p>' . 
                __('Settings saved.', 'image-payload-scanner') . '</p></div>';
        }

        // Get current settings
        $api_endpoint = get_option('ips_api_endpoint', 'http://localhost:5000');
        $auto_scan = get_option('ips_auto_scan', 0);
        $block_high_risk = get_option('ips_block_high_risk', 0);
        $sanitize_on_upload = get_option('ips_sanitize_on_upload', 0);
        $remove_metadata = get_option('ips_remove_metadata', 1);

        // Check connection to API
        $api_status = $this->check_api_connection($api_endpoint);
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Image Payload Scanner Settings', 'image-payload-scanner'); ?></h1>
            
            <div class="notice notice-warning">
                <p><strong><?php echo esc_html__('FOR EDUCATIONAL AND SECURITY RESEARCH PURPOSES ONLY', 'image-payload-scanner'); ?></strong></p>
            </div>
            
            <?php if ($api_status === true): ?>
                <div class="notice notice-success">
                    <p><?php echo esc_html__('API Connection: ', 'image-payload-scanner'); ?><strong><?php echo esc_html__('Connected', 'image-payload-scanner'); ?></strong></p>
                </div>
            <?php else: ?>
                <div class="notice notice-error">
                    <p><?php echo esc_html__('API Connection: ', 'image-payload-scanner'); ?><strong><?php echo esc_html__('Failed - ', 'image-payload-scanner'); ?><?php echo esc_html($api_status); ?></strong></p>
                    <p><?php echo esc_html__('Make sure the API server is running and accessible.', 'image-payload-scanner'); ?></p>
                </div>
            <?php endif; ?>
            
            <form method="post" action="">
                <?php wp_nonce_field('ips_settings_nonce'); ?>
                <input type="hidden" name="ips_settings" value="1">
                
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php echo esc_html__('API Endpoint', 'image-payload-scanner'); ?></th>
                        <td>
                            <input type="url" name="ips_api_endpoint" value="<?php echo esc_attr($api_endpoint); ?>" class="regular-text">
                            <p class="description"><?php echo esc_html__('Enter the URL where the Image Payload Injection API is running', 'image-payload-scanner'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__('Auto Scan Images', 'image-payload-scanner'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ips_auto_scan" value="1" <?php checked($auto_scan, 1); ?>>
                                <?php echo esc_html__('Automatically scan images when they are uploaded', 'image-payload-scanner'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__('Block High Risk Images', 'image-payload-scanner'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ips_block_high_risk" value="1" <?php checked($block_high_risk, 1); ?>>
                                <?php echo esc_html__('Block upload of high-risk images', 'image-payload-scanner'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__('Auto Sanitize', 'image-payload-scanner'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ips_sanitize_on_upload" value="1" <?php checked($sanitize_on_upload, 1); ?>>
                                <?php echo esc_html__('Automatically sanitize images when they are uploaded', 'image-payload-scanner'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__('Remove Metadata', 'image-payload-scanner'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="ips_remove_metadata" value="1" <?php checked($remove_metadata, 1); ?>>
                                <?php echo esc_html__('Remove metadata when sanitizing images', 'image-payload-scanner'); ?>
                            </label>
                        </td>
                    </tr>
                </table>
                
                <p class="submit">
                    <input type="submit" name="submit" id="submit" class="button button-primary" value="<?php echo esc_attr__('Save Settings', 'image-payload-scanner'); ?>">
                </p>
            </form>
        </div>
        <?php
    }

    /**
     * Media scanner page
     */
    public function media_page() {
        // Check user capabilities
        if (!current_user_can('upload_files')) {
            return;
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Image Security Scanner', 'image-payload-scanner'); ?></h1>
            
            <div class="notice notice-warning">
                <p><strong><?php echo esc_html__('FOR EDUCATIONAL AND SECURITY RESEARCH PURPOSES ONLY', 'image-payload-scanner'); ?></strong></p>
            </div>
            
            <div class="card">
                <h2><?php echo esc_html__('Batch Scan Images', 'image-payload-scanner'); ?></h2>
                <p><?php echo esc_html__('Scan all images in your media library for potential security issues.', 'image-payload-scanner'); ?></p>
                <button id="ips-batch-scan" class="button button-primary"><?php echo esc_html__('Start Batch Scan', 'image-payload-scanner'); ?></button>
                <div id="ips-batch-progress" style="display: none; margin-top: 10px;">
                    <p><?php echo esc_html__('Scanning images...', 'image-payload-scanner'); ?> <span id="ips-batch-count">0</span> <?php echo esc_html__('of', 'image-payload-scanner'); ?> <span id="ips-batch-total">0</span></p>
                    <div class="progress-bar-wrapper" style="height: 20px; width: 100%; background-color: #f0f0f0; border-radius: 3px;">
                        <div id="ips-batch-progress-bar" style="height: 100%; width: 0%; background-color: #2271b1;"></div>
                    </div>
                </div>
                <div id="ips-batch-results" style="display: none; margin-top: 15px;">
                    <h3><?php echo esc_html__('Scan Results', 'image-payload-scanner'); ?></h3>
                    <div class="ips-summary">
                        <p><?php echo esc_html__('Total Images:', 'image-payload-scanner'); ?> <span id="ips-total-count">0</span></p>
                        <p><?php echo esc_html__('High Risk:', 'image-payload-scanner'); ?> <span id="ips-high-risk">0</span></p>
                        <p><?php echo esc_html__('Medium Risk:', 'image-payload-scanner'); ?> <span id="ips-medium-risk">0</span></p>
                    </div>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th><?php echo esc_html__('Image', 'image-payload-scanner'); ?></th>
                                <th><?php echo esc_html__('Risk Level', 'image-payload-scanner'); ?></th>
                                <th><?php echo esc_html__('Issues', 'image-payload-scanner'); ?></th>
                                <th><?php echo esc_html__('Actions', 'image-payload-scanner'); ?></th>
                            </tr>
                        </thead>
                        <tbody id="ips-results-table">
                            <!-- Results will be added here -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Enqueue admin scripts and styles
     */
    public function enqueue_admin_scripts($hook) {
        // Only enqueue on our plugin pages and media pages
        if ($hook === 'settings_page_image-payload-scanner' || 
            $hook === 'media_page_image-payload-scanner-media' ||
            $hook === 'upload.php' ||
            $hook === 'post.php' ||
            $hook === 'post-new.php') {
            
            wp_enqueue_style(
                'ips-admin-styles',
                IPS_PLUGIN_URL . 'assets/css/admin.css',
                array(),
                IPS_VERSION
            );
            
            wp_enqueue_script(
                'ips-admin-script',
                IPS_PLUGIN_URL . 'assets/js/admin.js',
                array('jquery'),
                IPS_VERSION,
                true
            );
            
            wp_localize_script('ips-admin-script', 'ips_vars', array(
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('ips_nonce'),
                'api_endpoint' => get_option('ips_api_endpoint', 'http://localhost:5000'),
                'i18n' => array(
                    'analyzing' => __('Analyzing image...', 'image-payload-scanner'),
                    'sanitizing' => __('Sanitizing image...', 'image-payload-scanner'),
                    'error' => __('Error', 'image-payload-scanner'),
                    'success' => __('Success', 'image-payload-scanner'),
                    'high_risk' => __('High Risk', 'image-payload-scanner'),
                    'medium_risk' => __('Medium Risk', 'image-payload-scanner'),
                    'low_risk' => __('Low Risk', 'image-payload-scanner'),
                    'analyze' => __('Analyze', 'image-payload-scanner'),
                    'sanitize' => __('Sanitize', 'image-payload-scanner'),
                )
            ));
        }
    }

    /**
     * Check connection to the API server
     */
    private function check_api_connection($api_endpoint) {
        // Send a request to the API server
        $response = wp_remote_get($api_endpoint . '/api/analyze');
        
        // Check for error
        if (is_wp_error($response)) {
            return $response->get_error_message();
        }
        
        // Check status code
        $status_code = wp_remote_retrieve_response_code($response);
        if ($status_code !== 200 && $status_code !== 400) {
            return __('Unexpected status code: ', 'image-payload-scanner') . $status_code;
        }
        
        return true;
    }

    /**
     * Scan image before upload
     */
    public function pre_upload_scan($file) {
        // Check if auto-scan is enabled
        if (get_option('ips_auto_scan', 0) !== 1) {
            return $file;
        }
        
        // Check if file is an image
        $allowed_mime_types = array(
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/bmp',
            'image/svg+xml',
            'image/webp',
            'image/tiff',
        );
        
        if (!in_array($file['type'], $allowed_mime_types)) {
            return $file;
        }
        
        // Get API endpoint
        $api_endpoint = get_option('ips_api_endpoint', 'http://localhost:5000');
        
        try {
            // Send the image to the API for analysis
            $response = wp_remote_post($api_endpoint . '/api/analyze', array(
                'timeout' => 60,
                'body' => array(
                    'file' => file_get_contents($file['tmp_name']),
                    'filename' => $file['name'],
                ),
            ));
            
            // Check for error
            if (is_wp_error($response)) {
                return $file;
            }
            
            // Parse response
            $body = wp_remote_retrieve_body($response);
            $result = json_decode($body, true);
            
            // Block high-risk images if option is enabled
            if (get_option('ips_block_high_risk', 0) === 1 && 
                isset($result['risk_level']) && $result['risk_level'] === 'High') {
                $file['error'] = __('This image has been identified as high risk and cannot be uploaded. Please contact your administrator for more information.', 'image-payload-scanner');
                return $file;
            }
            
            // Sanitize image if option is enabled
            if (get_option('ips_sanitize_on_upload', 0) === 1) {
                // Send the image to the API for sanitization
                $sanitize_response = wp_remote_post($api_endpoint . '/api/sanitize', array(
                    'timeout' => 60,
                    'body' => array(
                        'file' => file_get_contents($file['tmp_name']),
                        'filename' => $file['name'],
                        'remove_metadata' => get_option('ips_remove_metadata', 1),
                    ),
                ));
                
                // Check for error
                if (!is_wp_error($sanitize_response)) {
                    $sanitize_body = wp_remote_retrieve_body($sanitize_response);
                    $sanitize_result = json_decode($sanitize_body, true);
                    
                    if (isset($sanitize_result['success']) && $sanitize_result['success'] === true) {
                        // Replace the uploaded file with the sanitized one
                        $sanitized_content = file_get_contents($sanitize_result['sanitized_url']);
                        file_put_contents($file['tmp_name'], $sanitized_content);
                    }
                }
            }
        } catch (Exception $e) {
            // Log the error but don't block the upload
            error_log('Image Payload Scanner error: ' . $e->getMessage());
        }
        
        return $file;
    }

    /**
     * Add scan button to media modal and edit screen
     */
    public function add_scan_button_to_media($form_fields, $post) {
        // Only for image attachments
        if (strpos($post->post_mime_type, 'image') === false) {
            return $form_fields;
        }
        
        $form_fields['ips_scan'] = array(
            'label' => __('Security Scan', 'image-payload-scanner'),
            'input' => 'html',
            'html' => '<button type="button" class="button ips-analyze-button" data-attachment-id="' . esc_attr($post->ID) . '">' .
                      __('Analyze', 'image-payload-scanner') . '</button> ' .
                      '<button type="button" class="button ips-sanitize-button" data-attachment-id="' . esc_attr($post->ID) . '">' .
                      __('Sanitize', 'image-payload-scanner') . '</button>' .
                      '<div class="ips-results" id="ips-results-' . esc_attr($post->ID) . '"></div>',
            'helps' => __('Analyze or sanitize this image for security issues', 'image-payload-scanner'),
        );
        
        return $form_fields;
    }

    /**
     * AJAX handler for analyzing images
     */
    public function ajax_analyze_image() {
        // Check nonce
        if (!check_ajax_referer('ips_nonce', 'nonce', false)) {
            wp_send_json_error(array('message' => __('Security check failed', 'image-payload-scanner')));
            wp_die();
        }
        
        // Check if attachment ID is provided
        if (!isset($_POST['attachment_id'])) {
            wp_send_json_error(array('message' => __('No attachment ID provided', 'image-payload-scanner')));
            wp_die();
        }
        
        // Get attachment
        $attachment_id = intval($_POST['attachment_id']);
        $file_path = get_attached_file($attachment_id);
        
        if (!$file_path || !file_exists($file_path)) {
            wp_send_json_error(array('message' => __('Attachment file not found', 'image-payload-scanner')));
            wp_die();
        }
        
        // Get API endpoint
        $api_endpoint = get_option('ips_api_endpoint', 'http://localhost:5000');
        
        try {
            // Send the image to the API for analysis
            $response = wp_remote_post($api_endpoint . '/api/analyze', array(
                'timeout' => 60,
                'body' => array(
                    'file' => file_get_contents($file_path),
                    'filename' => basename($file_path),
                ),
            ));
            
            // Check for error
            if (is_wp_error($response)) {
                wp_send_json_error(array('message' => $response->get_error_message()));
                wp_die();
            }
            
            // Parse response
            $body = wp_remote_retrieve_body($response);
            $result = json_decode($body, true);
            
            // Send response
            wp_send_json_success($result);
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
        
        wp_die();
    }

    /**
     * AJAX handler for sanitizing images
     */
    public function ajax_sanitize_image() {
        // Check nonce
        if (!check_ajax_referer('ips_nonce', 'nonce', false)) {
            wp_send_json_error(array('message' => __('Security check failed', 'image-payload-scanner')));
            wp_die();
        }
        
        // Check if attachment ID is provided
        if (!isset($_POST['attachment_id'])) {
            wp_send_json_error(array('message' => __('No attachment ID provided', 'image-payload-scanner')));
            wp_die();
        }
        
        // Get attachment
        $attachment_id = intval($_POST['attachment_id']);
        $file_path = get_attached_file($attachment_id);
        
        if (!$file_path || !file_exists($file_path)) {
            wp_send_json_error(array('message' => __('Attachment file not found', 'image-payload-scanner')));
            wp_die();
        }
        
        // Get API endpoint
        $api_endpoint = get_option('ips_api_endpoint', 'http://localhost:5000');
        
        try {
            // Send the image to the API for sanitization
            $response = wp_remote_post($api_endpoint . '/api/sanitize', array(
                'timeout' => 60,
                'body' => array(
                    'file' => file_get_contents($file_path),
                    'filename' => basename($file_path),
                    'remove_metadata' => get_option('ips_remove_metadata', 1),
                ),
            ));
            
            // Check for error
            if (is_wp_error($response)) {
                wp_send_json_error(array('message' => $response->get_error_message()));
                wp_die();
            }
            
            // Parse response
            $body = wp_remote_retrieve_body($response);
            $result = json_decode($body, true);
            
            if (isset($result['success']) && $result['success'] === true && isset($result['sanitized_url'])) {
                // Get sanitized image content
                $sanitized_response = wp_remote_get($result['sanitized_url']);
                
                if (!is_wp_error($sanitized_response)) {
                    $sanitized_content = wp_remote_retrieve_body($sanitized_response);
                    
                    // Backup original file
                    $backup_path = $file_path . '.backup';
                    if (!file_exists($backup_path)) {
                        copy($file_path, $backup_path);
                    }
                    
                    // Replace the original file with the sanitized one
                    file_put_contents($file_path, $sanitized_content);
                    
                    // Update attachment metadata
                    wp_update_attachment_metadata(
                        $attachment_id,
                        wp_generate_attachment_metadata($attachment_id, $file_path)
                    );
                    
                    // Clear any caches
                    clean_attachment_cache($attachment_id);
                    
                    // Add success message
                    $result['message'] = __('Image sanitized successfully', 'image-payload-scanner');
                }
            }
            
            // Send response
            wp_send_json_success($result);
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
        
        wp_die();
    }
}

// Initialize the plugin
function ips_init() {
    new Image_Payload_Scanner();
}
add_action('plugins_loaded', 'ips_init');