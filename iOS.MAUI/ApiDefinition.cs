using Foundation;
namespace ApproovSDK
{

    // The first step to creating a binding is to add your native framework ("MyLibrary.xcframework")
    // to the project.
    // Open your binding csproj and add a section like this
    // <ItemGroup>
    //   <NativeReference Include="MyLibrary.xcframework">
    //     <Kind>Framework</Kind>
    //     <Frameworks></Frameworks>
    //   </NativeReference>
    // </ItemGroup>
    //
    // Once you've added it, you will need to customize it for your specific library:
    //  - Change the Include to the correct path/name of your library
    //  - Change Kind to Static (.a) or Framework (.framework/.xcframework) based upon the library kind and extension.
    //    - Dynamic (.dylib) is a third option but rarely if ever valid, and only on macOS and Mac Catalyst
    //  - If your library depends on other frameworks, add them inside <Frameworks></Frameworks>
    // Example:
    // <NativeReference Include="libs\MyTestFramework.xcframework">
    //   <Kind>Framework</Kind>
    //   <Frameworks>CoreLocation ModelIO</Frameworks>
    // </NativeReference>
    // 
    // Once you've done that, you're ready to move on to binding the API...
    //
    // Here is where you'd define your API definition for the native Objective-C library.
    //
    // For example, to bind the following Objective-C class:
    //
    //     @interface Widget : NSObject {
    //     }
    //
    // The C# binding would look like this:
    //
    //     [BaseType (typeof (NSObject))]
    //     interface Widget {
    //     }
    //
    // To bind Objective-C properties, such as:
    //
    //     @property (nonatomic, readwrite, assign) CGPoint center;
    //
    // You would add a property definition in the C# interface like so:
    //
    //     [Export ("center")]
    //     CGPoint Center { get; set; }
    //
    // To bind an Objective-C method, such as:
    //
    //     -(void) doSomething:(NSObject *)object atIndex:(NSInteger)index;
    //
    // You would add a method definition to the C# interface like so:
    //
    //     [Export ("doSomething:atIndex:")]
    //     void DoSomething (NSObject object, nint index);
    //
    // Objective-C "constructors" such as:
    //
    //     -(id)initWithElmo:(ElmoMuppet *)elmo;
    //
    // Can be bound as:
    //
    //     [Export ("initWithElmo:")]
    //     NativeHandle Constructor (ElmoMuppet elmo);
    //
    // For more information, see https://aka.ms/ios-binding
    //

    // @interface ApproovTokenFetchResult : NSObject
    [BaseType(typeof(NSObject))]
    interface ApproovTokenFetchResult
    {
        // @property (readonly) ApproovTokenFetchStatus status;
        [Export("status")]
        ApproovTokenFetchStatus Status();

        // @property (readonly) NSString * _Nonnull token;
        [Export("token")]
        string Token();

        // @property (readonly) NSString * _Nullable secureString;
        [NullAllowed, Export("secureString")]
        string SecureString();

        // @property (readonly) NSString * _Nonnull ARC;
        [Export("ARC")]
        string ARC();

        // @property (readonly) NSString * _Nonnull rejectionReasons;
        [Export("rejectionReasons")]
        string RejectionReasons();

        // @property (readonly) BOOL isConfigChanged;
        [Export("isConfigChanged")]
        bool IsConfigChanged();

        // @property (readonly) BOOL isForceApplyPins;
        [Export("isForceApplyPins")]
        bool IsForceApplyPins();

        // @property (readonly) NSData * _Nullable measurementConfig;
        [NullAllowed, Export("measurementConfig")]
        NSData MeasurementConfig();

        // -(NSString * _Nonnull)loggableToken;
        [Export("loggableToken")]
        //[Verify (MethodToProperty)]
        string LoggableToken();
    }

    // typedef void (^ApproovTokenFetchCallback)(ApproovTokenFetchResult * _Nonnull);
    delegate void ApproovTokenFetchCallback(ApproovTokenFetchResult arg0);

    // @interface Approov : NSObject
    [BaseType(typeof(NSObject))]
    interface Approov
    {
        // +(NSString * _Nonnull)stringFromApproovTokenFetchStatus:(ApproovTokenFetchStatus)approovTokenFetchStatus;
        [Static]
        [Export("stringFromApproovTokenFetchStatus:")]
        string StringFromApproovTokenFetchStatus(ApproovTokenFetchStatus approovTokenFetchStatus);

        // +(BOOL)initialize:(NSString * _Nonnull)initialConfig updateConfig:(NSString * _Nullable)updateConfig comment:(NSString * _Nullable)comment error:(NSError * _Nullable * _Nullable)error;
        [Static]
        [Export("initialize:updateConfig:comment:error:")]
        bool Initialize(string initialConfig, [NullAllowed] string updateConfig, [NullAllowed] string comment, [NullAllowed] out NSError error);

        // +(NSString * _Nullable)fetchConfig;
        [Static]
        [NullAllowed, Export("fetchConfig")]
        //[Verify (MethodToProperty)]
        string FetchConfig();

        // +(NSDictionary<NSString *,NSArray<NSString *> *> * _Nullable)getPins:(NSString * _Nonnull)pinType;
        [Static]
        [Export("getPins:")]
        [return: NullAllowed]
        NSDictionary<NSString, NSArray<NSString>> GetPins(string pinType);

        // +(NSString * _Nullable)getPinsJSON:(NSString * _Nonnull)pinType;
        [Static]
        [Export("getPinsJSON:")]
        [return: NullAllowed]
        string GetPinsJSON(string pinType);

        // +(void)fetchApproovToken:(ApproovTokenFetchCallback _Nonnull)callbackHandler :(NSString * _Nonnull)url;
        [Static]
        [Export("fetchApproovToken::")]
        void FetchApproovToken(ApproovTokenFetchCallback callbackHandler, string url);

        // +(ApproovTokenFetchResult * _Nonnull)fetchApproovTokenAndWait:(NSString * _Nonnull)url;
        [Static]
        [Export("fetchApproovTokenAndWait:")]
        ApproovTokenFetchResult FetchApproovTokenAndWait(string url);

        // +(void)fetchCustomJWT:(ApproovTokenFetchCallback _Nonnull)callbackHandler :(NSString * _Nonnull)payload;
        [Static]
        [Export("fetchCustomJWT::")]
        void FetchCustomJWT(ApproovTokenFetchCallback callbackHandler, string payload);

        // +(ApproovTokenFetchResult * _Nonnull)fetchCustomJWTAndWait:(NSString * _Nonnull)payload;
        [Static]
        [Export("fetchCustomJWTAndWait:")]
        ApproovTokenFetchResult FetchCustomJWTAndWait(string payload);

        // +(void)fetchSecureString:(ApproovTokenFetchCallback _Nonnull)callbackHandler :(NSString * _Nonnull)key :(NSString * _Nullable)newDef;
        [Static]
        [Export("fetchSecureString:::")]
        void FetchSecureString(ApproovTokenFetchCallback callbackHandler, string key, [NullAllowed] string newDef);

        // +(ApproovTokenFetchResult * _Nonnull)fetchSecureStringAndWait:(NSString * _Nonnull)key :(NSString * _Nullable)newDef;
        [Static]
        [Export("fetchSecureStringAndWait::")]
        ApproovTokenFetchResult FetchSecureStringAndWait(string key, [NullAllowed] string newDef);

        // +(void)setUserProperty:(NSString * _Nullable)property;
        [Static]
        [Export("setUserProperty:")]
        void SetUserProperty([NullAllowed] string property);

        // +(void)setDataHashInToken:(NSString * _Nonnull)data;
        [Static]
        [Export("setDataHashInToken:")]
        void SetDataHashInToken(string data);

        // +(NSData * _Nullable)getIntegrityMeasurementProof:(NSData * _Nonnull)nonce :(NSData * _Nonnull)measurementConfig;
        [Static]
        [Export("getIntegrityMeasurementProof::")]
        [return: NullAllowed]
        NSData GetIntegrityMeasurementProof(NSData nonce, NSData measurementConfig);

        // +(NSData * _Nullable)getDeviceMeasurementProof:(NSData * _Nonnull)nonce :(NSData * _Nonnull)measurementConfig;
        [Static]
        [Export("getDeviceMeasurementProof::")]
        [return: NullAllowed]
        NSData GetDeviceMeasurementProof(NSData nonce, NSData measurementConfig);

        // +(NSString * _Nullable)getDeviceID;
        [Static]
        [NullAllowed, Export("getDeviceID")]
        //[Verify (MethodToProperty)]
        string DeviceID();

        // +(NSString * _Nullable)getMessageSignature:(NSString * _Nonnull)message;
        [Static]
        [Export("getMessageSignature:")]
        [return: NullAllowed]
        string GetMessageSignature(string message);
    }

}


