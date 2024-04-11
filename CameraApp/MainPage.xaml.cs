using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Windows.Media.Capture;
using Windows.Media.MediaProperties;
using Windows.Storage;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Media;

namespace CameraApp
{
    public sealed partial class MainPage : Page
    {
        private MediaCapture _mediaCapture;
        private bool _isPreviewing;
        private object photoRes = null;
        private object previewRes = null;

        public MainPage()
        {
            this.InitializeComponent();
            this.Loaded += MainPage_Loaded;

            // Subscribe to the SelectionChanged event for both combo boxes
            PhotoResolutionComboBox.SelectionChanged += PhotoResolutionComboBox_SelectionChanged;
            CameraPreviewResolutionComboBox.SelectionChanged += CameraPreviewResolutionComboBox_SelectionChanged;
        }

        private async void MainPage_Loaded(object sender, RoutedEventArgs e)
        {
            await InitializeCameraAsync();
        }

        private async Task InitializeCameraAsync()
        {
            if (_mediaCapture == null)
            {
                _mediaCapture = new MediaCapture();
                await _mediaCapture.InitializeAsync();

                // Check if resolutions are selected and set them
                if (photoRes != null)
                {
                    PhotoResolutionComboBox.SelectedItem = photoRes;
                }
                if (previewRes != null)
                {
                    CameraPreviewResolutionComboBox.SelectedItem = previewRes;
                }

                // Populate resolutions if not already done
                if (PhotoResolutionComboBox.Items.Count == 0 || CameraPreviewResolutionComboBox.Items.Count == 0)
                {
                    PopulateResolutionComboBoxes();
                }

                PreviewControl.Source = _mediaCapture;
            }
        }

        private void PopulateResolutionComboBoxes()
        {
            IEnumerable<StreamResolution> allProperties = _mediaCapture.VideoDeviceController.GetAvailableMediaStreamProperties(MediaStreamType.VideoPreview).Select(x => new StreamResolution(x));
            IEnumerable<StreamResolution> allPhotoProperties = _mediaCapture.VideoDeviceController.GetAvailableMediaStreamProperties(MediaStreamType.Photo).Select(x => new StreamResolution(x));

            allProperties = allProperties.OrderByDescending(x => x.Height * x.Width * x.FrameRate);
            allPhotoProperties = allPhotoProperties.OrderByDescending(x => x.Height * x.Width);

            CameraPreviewResolutionComboBox.ItemsSource = allProperties;
            CameraPreviewResolutionComboBox.DisplayMemberPath = "Name";
            CameraPreviewResolutionComboBox.SelectedIndex = 0;

            PhotoResolutionComboBox.ItemsSource = allPhotoProperties;
            PhotoResolutionComboBox.DisplayMemberPath = "Name";
            PhotoResolutionComboBox.SelectedIndex = 0;

            // Debug resolutions to log file
            DebugResolutions(allProperties, allPhotoProperties);
        }

        private async void DebugResolutions(IEnumerable<StreamResolution> previewResolutions, IEnumerable<StreamResolution> photoResolutions)
        {
            try
            {
                // Get the user's My Documents folder
                StorageFolder storageFolder = KnownFolders.PicturesLibrary;
                // Create a new file named "log.txt" in the My Documents folder
                StorageFile logFile = await storageFolder.CreateFileAsync("log.txt", CreationCollisionOption.ReplaceExisting);

                // Write preview resolutions to the log file
                using (StreamWriter writer = new StreamWriter(await logFile.OpenStreamForWriteAsync()))
                {
                    writer.WriteLine("Preview Resolutions:");
                    foreach (var resolution in previewResolutions)
                    {
                        writer.WriteLine($"Name: {resolution.Name}, Width: {resolution.Width}, Height: {resolution.Height}, FrameRate: {resolution.FrameRate}");
                    }
                    writer.WriteLine("\nPhoto Resolutions:");
                    foreach (var resolution in photoResolutions)
                    {
                        writer.WriteLine($"Name: {resolution.Name}, Width: {resolution.Width}, Height: {resolution.Height}");
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle exception
            }
        }

        private async void PhotoResolutionComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Handle the selection change for the photo resolution
            if (PhotoResolutionComboBox.SelectedItem != null)
            {
                photoRes = PhotoResolutionComboBox.SelectedItem;
                var selectedResolution = (dynamic)photoRes;
                // Do something with the selected resolution, such as setting it for photo capture
            }
        }

        private async void CameraPreviewResolutionComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Handle the selection change for the camera preview resolution
            if (CameraPreviewResolutionComboBox.SelectedItem != null)
            {
                previewRes = CameraPreviewResolutionComboBox.SelectedItem;
                var selectedResolution = (dynamic)previewRes;
                // Do something with the selected resolution, such as setting it for camera preview
            }
        }

        private async void StartPreviewButton_Click(object sender, RoutedEventArgs e)
        {
            if (!_isPreviewing)
            {
                if (previewRes != null)
                {
                    debug("SetMediaStreamPropertiesAsync: VideoPreview");
                    try
                    {
                        await _mediaCapture.VideoDeviceController.SetMediaStreamPropertiesAsync(MediaStreamType.VideoPreview, ((StreamResolution)previewRes).EncodingProperties);
                    }
                    catch(Exception exc)
                    {
                        debug(exc.Message);

                    }
                    debug("SetMediaStreamPropertiesAsync: PHOTO");
                    try
                    {
                        await _mediaCapture.VideoDeviceController.SetMediaStreamPropertiesAsync(MediaStreamType.Photo, (VideoEncodingProperties)photoRes);
                        
                    }
                    catch (Exception exc2)
                    {
                        debug(exc2.Message);
                    }

                    
                }

                debug("StartPreviewAsync");
                await _mediaCapture.StartPreviewAsync();
                _isPreviewing = true;
            }
        }

        private async void StopPreviewButton_Click(object sender, RoutedEventArgs e)
        {
            if (_isPreviewing)
            {
                await _mediaCapture.StopPreviewAsync();
                _isPreviewing = false;
            }
        }
        int cmdCount;
        void debug(String txt)
        {
            DebugText.Document.Selection.SetText(Windows.UI.Text.TextSetOptions.None, $"{cmdCount++}: {txt}\n");

        }
    }
}
