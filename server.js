const express = require("express");
const mongoose = require("mongoose");
const bodyParse = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookiesParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");
const http = require("http");
const { Server } = require("socket.io");
const { startOfDay, endOfDay } = require("date-fns");
const axios = require("axios");
require("dotenv").config();

async function sendSMS(contactNumber, message) {
  const url = " https://api.semaphore.co/api/v4/messages";
  const apiKey = process.env.SEMAPHORE_API_KEY;

  try {
    const response = await axios.post(url, {
      apikey: apiKey,
      number: contactNumber,
      message: message,
      sendername: "VETWELLNESS",
    });

    console.log("SMS sent successfully:", response.data);
  } catch (error) {
    console.error(
      "Error sending SMS:",
      error.response ? error.response.data : error.message
    );
  }
}

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "https://www.docjhayvetclinic.com",
    credentials: true,
  },
});

const PORT = process.env.PORT || 5000;

const JWT_SECRET = "usertoken";

app.use((req, res, next) => {
  const allowedOrigins = [
    "https://www.docjhayvetclinic.com",
    "https://vet-frontend-jh78.onrender.com",
  ];
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    );
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }

  next();
});

app.use(bodyParse.json());
app.use(cookiesParser());

mongoose.connect(
  "mongodb+srv://vetsystem28:hw2W7UI0TUCjlllY@vet.3abxi.mongodb.net/?retryWrites=true&w=majority&appName=VET"
);

const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

const userSchema = new mongoose.Schema({
  userId: { type: String, unique: true },
  email: { type: String, unique: true },
  name: String,
  password: String,
  address: String,
  contactNumber: Number,
  role: { type: String, enum: ["user", "admin"], default: "user" },
});
const User = mongoose.model("User", userSchema);

const appointmentSchema = new mongoose.Schema({
  appointmentId: { type: String, unique: true },
  userId: { type: String, required: true },
  name: String,
  address: String,
  email: String,
  contactNumber: String,
  petType: String,
  breed: String,
  appointmentDateTime: String,
  serviceOffered: {
    type: String,
    enum: [
      "Vaccination",
      "Deworming",
      "Grooming",
      "Surgery",
      "Consultation",
      "Treatment",
      "Confinement",
      "Pet Boarding",
      "Laboratory",
    ],
    required: true,
  },
  status: {
    type: String,
    enum: ["Pending", "Accepted", "Rejected", "Done"],
    default: "Pending",
  },
});
const Appointment = mongoose.model("Appointment", appointmentSchema);

const petReportSchema = new mongoose.Schema(
  {
    petReportId: { type: String, unique: true },

    email: { type: String, required: true },
    status: { type: String, default: "Pending" },
    petInfo: {
      name: { type: String },
      birthday: { type: Date },
      colorMarkings: { type: String },
      petType: { type: String },
      breed: { type: String },
    },
    ownerDetails: {
      name: { type: String },
      appointmentDate: { type: Date },
      address: { type: String },
      contactNumber: { type: String },
    },
    veterinarianDetails: {
      name: { type: String },
      clinicHospital: { type: String },
      address: { type: String },
      contactNumber: { type: String },
    },
    parasitesTreatment: {
      date: { type: Date },
      weight: { type: Number },
      productName: { type: String },
      veterinarian: { type: String },
    },
    rabiesVaccination: {
      date: { type: Date },
      vaccineDescription: { type: String },
      nextVaccinationDue: { type: Date },
      veterinarian: { type: String },
    },
    multivalentVaccination: {
      date: { type: Date },
      vaccineDescription: { type: String },
      nextVaccinationDue: { type: Date },
      veterinarian: { type: String },
    },
    serviceDetails: {
      service: { type: String, default: "N/A" },
    },
    appointmentId: { type: String, required: true, unique: true },
  },
  { timestamps: true }
);

const PetReport = mongoose.model("PetReport", petReportSchema);

const messageSchema = new mongoose.Schema({
  appointmentId: { type: String, required: true },
  sender: { type: String, required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
});

const Message = mongoose.model("Message", messageSchema);

io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);

  socket.on("joinRoom", ({ appointmentId }) => {
    socket.join(appointmentId);
    console.log(`User ${socket.id} joined room: ${appointmentId}`);
  });

  socket.on("leaveRoom", ({ appointmentId }) => {
    socket.leave(appointmentId);
    console.log(`User ${socket.id} left room: ${appointmentId}`);
  });

  socket.on("sendMessage", async ({ appointmentId, sender, content }) => {
    try {
      console.log("Received sendMessage event:", {
        appointmentId,
        sender,
        content,
      });

      if (!appointmentId || !sender || !content) {
        console.error("Invalid message data:", {
          appointmentId,
          sender,
          content,
        });
        return;
      }

      const newMessage = new Message({
        appointmentId,
        sender,
        content,
        timestamp: new Date(),
      });

      await newMessage.save();
      console.log("Message saved successfully:", newMessage);

      io.to(appointmentId).emit("receiveMessage", newMessage);
    } catch (error) {
      console.error("Error saving message:", error);
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
  });
});

app.post("/api/signup", async (req, res) => {
  const { email, name, password, address, contactNumber, role } = req.body;
  try {
    const userId = uuidv4();

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      userId,
      email,
      name,
      password: hashedPassword,
      address,
      contactNumber,
      role,
    });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch {
    res.status(500).json({ error: "Failed to register user" });
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find();
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign(
      { userId: user.userId, role: user.role },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
    res.status(200).json({
      message: "Logged in successfully",
      user,
    });
  } catch (error) {
    console.error("Login error", error);
    res.status(500).json({ error: "Failed to login user" });
  }
});

const authenticate = (req, res, next) => {
  console.log("Headers:", req.headers);
  console.log("Cookies:", req.cookies);
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

app.post("/api/appointment", authenticate, async (req, res) => {
  const { userId } = req.user;
  const {
    name,
    address,
    email,
    contactNumber,
    petType,
    breed,
    appointmentDateTime,
    serviceOffered,
  } = req.body;

  try {
    const appointmentDate = new Date(appointmentDateTime);

    if (isNaN(appointmentDate)) {
      console.error("Invalid appointment date:", appointmentDateTime);
      return res.status(400).json({ error: "Invalid appointment date" });
    }

    const startOfDayDate = startOfDay(appointmentDate).toISOString();
    const endOfDayDate = endOfDay(appointmentDate).toISOString();

    const appointmentCount = await Appointment.countDocuments({
      userId,
      appointmentDateTime: {
        $gte: startOfDayDate,
        $lte: endOfDayDate,
      },
    });

    if (appointmentCount >= 2) {
      console.log(
        "Maximum appointments reached for the day:",
        appointmentCount
      );
      return res
        .status(400)
        .json({ error: "You can only book 2 appointments per day." });
    }

    const appointmentId = uuidv4();
    const newAppointment = new Appointment({
      appointmentId,
      userId,
      name,
      address,
      email,
      contactNumber,
      petType,
      breed,
      appointmentDateTime,
      serviceOffered,
    });

    await newAppointment.save();

    res.status(201).json({ message: "Appointment saved!" });
  } catch (error) {
    console.error("Error saving appointment:", error);
    res.status(500).json({ error: "Failed to save appointment" });
  }
});

app.get("/api/appointments", authenticate, async (req, res) => {
  try {
    const appointments = await Appointment.find();
    if (appointments.length === 0) {
      return res.status(404).json({ message: "No appointments found" });
    }
    res.status(200).json(appointments);
  } catch (error) {
    console.error("Error fetching appointments:", error);
    res.status(500).json({ error: "Failed to fetch  appointments" });
  }
});

app.put("/api/appointment/:appointmentId", authenticate, async (req, res) => {
  const { appointmentId } = req.params;
  const { status } = req.body;

  try {
    const appointment = await Appointment.findOneAndUpdate(
      { appointmentId },
      { status },
      { new: true }
    );

    if (!appointment) {
      return res.status(404).json({ message: "Appointment not found" });
    }

    if (status === "Accepted") {
      const message = `Hello ${appointment.name}, your appointment for ${appointment.serviceOffered} on ${appointment.appointmentDate} has been accepted.`;
      await sendSMS(appointment.contactNumber, message);
    }

    res.status(200).json({ message: "Appointment updated", appointment });
  } catch (error) {
    console.error("Error updating appointment status:", error);
    res.status(500).json({ error: "Failed to update appointment status" });
  }
});

app.post("/api/messages", authenticate, async (req, res) => {
  const { appointmentId, sender, content } = req.body;

  try {
    if (!appointmentId || !sender || !content) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const newMessage = new Message({ appointmentId, sender, content });
    await newMessage.save();

    res.status(201).json({ message: "Message saved successfully", newMessage });

    io.to(appointmentId).emit("receiveMessage", newMessage);
  } catch (error) {
    console.error("Error saving message:", error);
    res.status(500).json({ error: "Failed to save message" });
  }
});

app.get("/api/messages/:appointmentId", authenticate, async (req, res) => {
  const { appointmentId } = req.params;

  try {
    const messages = await Message.find({ appointmentId }).sort({
      timestamp: 1,
    });
    res.status(200).json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

app.post("/api/pet-reports/:appointmentId", authenticate, async (req, res) => {
  const { appointmentId } = req.params;
  const reportData = req.body;

  try {
    const petReportId = uuidv4();
    const reportToSave = {
      petReportId,
      appointmentId,
      ...reportData,
    };

    const petReport = await PetReport.findOneAndUpdate(
      { appointmentId },
      { $set: reportToSave },
      { new: true, upsert: true }
    );

    res
      .status(200)
      .json({ message: "Pet report saved successfully", petReport });
  } catch (error) {
    console.error("Error saving pet report:", error);
    res.status(500).json({ error: "Failed to save pet report" });
  }
});

app.get("/api/pet-reports", authenticate, async (req, res) => {
  try {
    const petReports = await PetReport.find();

    res
      .status(200)
      .json({ message: "All pet reports retrieved successfully", petReports });
  } catch (error) {
    console.error("Error retrieving pet reports:", error);
    res.status(500).json({ error: "Failed to retrieve pet reports" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.status(200).json({ message: "Logged out successfully" });
});

app.get("/api/protected", authenticate, (req, res) => {
  res.status(200).json({ message: "You have access to this protected route" });
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
