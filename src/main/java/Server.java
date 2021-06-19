import com.google.gson.JsonObject;
import cryptography.key.PrivateKey;
import cryptography.key.PublicKey;

import java.awt.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;

import com.google.gson.Gson;
import model.ImageInfo;
import model.User;
import org.json.JSONArray;
import org.json.JSONObject;
import request.ImagePostRequest;
import request.LoginRequest;
import request.PublicKeyRequestModel;
import request.RegisterRequest;
import response.NotificationResponse;
import response.RegisterResponse;
import response.Response;
import util.Constants;
import util.Helper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import static util.Constants.RequestType.REGISTER;


public class Server {

    private static ServerSocket server;
    static Gson gson = new Gson();
    //socket server port on which it will listen
    private static int port = 9876;
    private static PublicKey serverPublicKey = new PublicKey(new BigInteger(Constants.KEY_N, 16), new BigInteger(Constants.KEY_E, 16));
    private static PrivateKey serverPrivateKey = new PrivateKey(new BigInteger(Constants.KEY_N, 16), new BigInteger(Constants.KEY_D, 16));

    private static HashMap<String, User> userMap = new HashMap<String, User>();
    private static ArrayList<ImageInfo> images = new ArrayList<>();
    private static HashMap<String, ArrayList<ImageInfo>> notificationMap = new HashMap<>();



    public static void startListening() throws IOException, ClassNotFoundException {
        server = new ServerSocket(port);

        //keep listens indefinitely until receives 'exit' call or program terminates
        while (true) {
            Socket socket = server.accept();
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            String request = (String) ois.readObject();

            final Response response = handleRequest(request);
            final String responseJson = gson.toJson(response);

            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            //write object to Socket
            oos.writeObject(responseJson);
            //close resources
            ois.close();
            oos.close();
            socket.close();
        }
    }

    private static Response handleRequest(String request) {

        final JSONObject requestJson = new JSONObject(request);
        System.out.println(requestJson);
        final String requestType = requestJson.getString("requestType");
        final Constants.RequestType reqType = Constants.RequestType.valueOf(requestType);

        switch (reqType) {
            case REGISTER:
                final RegisterRequest registerRequest = gson.fromJson(request, RegisterRequest.class);
                return registerNewUser(registerRequest);
            case LOGIN:
                final LoginRequest loginRequest = gson.fromJson(request, LoginRequest.class);
                return login(loginRequest);
            case POST_IMAGE:
                final ImagePostRequest postRequest = gson.fromJson(request, ImagePostRequest.class);
                return postImage(postRequest);
            case NOTIFICATION:
                return checkForNotification(requestJson);
        }

        return null;
    }


    private static Response registerNewUser(RegisterRequest request) {

        final String username = request.getUsername();

        if (userMap.containsKey(username)) {
            return new Response(400, "Username taken by another user!");
        }

        final String userCertificate = createUserCertificate(username, request.getPublicKey());
        final User user = new User(username, request.getPassword(), userCertificate);
        userMap.put(username, user);
        notificationMap.put(username, new ArrayList<>());

        return new RegisterResponse(201, "Register successful",userCertificate);
    }

    private static String createUserCertificate(String username, PublicKeyRequestModel publicKey) {

        final JSONObject userJson = new JSONObject()
                .put("username", username);

        final JSONObject userPublicKey = new JSONObject()
                .put("n", publicKey.getN())
                .put("e", publicKey.getE());
        userJson.put("publicKey", userPublicKey);
        final String s = Helper.decodeStringToHex(userJson.toString()).toUpperCase();
        return serverPrivateKey.encrypt(s);
    }

    private static Response login(LoginRequest loginRequest) {
        final String username = loginRequest.getUsername();

        if (!userMap.containsKey(username)) {
            return new Response(401, "This username not register yet!");
        }

        final User user = userMap.get(username);
        final String password = loginRequest.getPassword();

        if(!user.getPassword().equals(password)) return new Response(401, "Password is wrong!");

        return new Response(200, "Login successful");
    }

    private static Response postImage(ImagePostRequest postRequest) {

        final String key = postRequest.getKey();

        final String decryptedKey = serverPrivateKey.decrypt(key);
        final String decryptedIV = serverPrivateKey.decrypt(postRequest.getIV());

        final ImageInfo imageInfo = new ImageInfo(postRequest.getImage(), postRequest.getImageName(), postRequest.getOwner(), decryptedKey, postRequest.getDigitalSignature(), decryptedIV);
        images.add(imageInfo);

        final Set<String> usernames = userMap.keySet();

        usernames.forEach(username -> {
            if(!username.equals(postRequest.getOwner())) {
                final ArrayList<ImageInfo> images = notificationMap.get(username);
                images.add(imageInfo);
            }
        });
        return new Response(200, "Imaged posted successfully");
    }

    private static Response checkForNotification(JSONObject request) {

        final String username = request.getString("username");

        final ArrayList<ImageInfo> imageInfos = notificationMap.get(username);

        if(imageInfos.isEmpty()) return new Response(400, "");
        JSONArray imagesForNotificate = new JSONArray();
        imageInfos.forEach(image -> {
            final JSONObject imageInfo = new JSONObject()
                    .put("imageName", image.getImageName())
                    .put("owner", image.getOwner());

            imagesForNotificate.put(imageInfo);
        });
        imageInfos.clear();

        return new NotificationResponse(200,"",imagesForNotificate.toString());
    }

}
