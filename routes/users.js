const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = express.Router();

const User = require("../models/user");

// router.get("/", async (req, res) => {
//   const userList = await User.find().select("-passwordHash");

//   if (!userList) {
//     res.status(500).json({ success: false });
//   }
//   res.send(userList);
// });
const auth = (req, res, next) => {
  try {
    const token = req.header("x-auth-token");
    if (!token)
      return res.status(401).json({ error: "No auth token, access denied" });
    const verified = jwt.verify(token, process.env.secret);
    if (!verified)
      return res
        .status(401)
        .json({ error: "Token verification failed, authorization denied" });
    req.user = verified.userID;
    req.token = token;
    next();
  } catch (e) {}
};

router.get("/", auth, async (req, res) => {
  const user = await User.findById(req.user);
  if (!user) {
    res.status(500).json({
      success: false,
      message: "The user with the given ID not exists",
    });
  }
  res.status(200).json({ ...user._doc, token: req.token });
});

router.patch("/:id", auth, async (req, res) => {
  try {
    const id = req.params.id;
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Update user fields
    user.name = req.body.name;
    user.email = req.body.email;
    user.phone = req.body.phone;
    user.isAdmin = req.body.isAdmin;
    user.street = req.body.street;
    user.apartment = req.body.apartment;
    user.zip = req.body.zip;
    user.city = req.body.city;
    user.country = req.body.country;

    // Save the updated user
    await user.save();

    return res
      .status(200)
      .json({ token: req.token,...user._doc }); // Return the token response
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Internal server error" });
  }
});

router.post("/register", async (req, res) => {
  try {
    let user = new User({
      name: req.body.name,
      email: req.body.email,
      passwordHash: bcrypt.hashSync(req.body.password, 10),
      phone: req.body.phone,
      isAdmin: req.body.isAdmin,
      street: req.body.street,
      apartment: req.body.apartment,
      zip: req.body.zip,
      city: req.body.city,
      country: req.body.country,
    });

    user = await user.save();

    if (!user) return res.status(404).send("User cannot be created");
    res.send(user);
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

router.delete("/:id", (req, res) => {
  User.findByIdAndRemove(req.params.id)
    .then((user) => {
      if (user) {
        return res
          .status(200)
          .json({ success: true, message: "User deleted successfully" });
      } else {
        return res
          .status(404)
          .json({ success: false, message: "User cannot find" });
      }
    })
    .catch((err) => {
      return res.status(400).json({ success: false, error: err });
    });
});
router.post("/tokenIsValid", async (req, res) => {
  try {
    const token = req.header("x-auth-token");
    if (!token) return res.json(false);
    const verified = jwt.verify(token, process.env.secret);
    if (!verified) return res.json(false);

    const user = await User.findById(verified.userID);
    if (!user) return res.json(false);
    res.json(true);
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});
router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    const secret = process.env.secret;

    if (!user) {
      return res.status(400).json({ error: "Incorrect Email or password" });
    }
    console.log(req.body);
    console.log(user.passwordHash);
    console.log(bcrypt.compareSync(req.body.password, user.passwordHash));
    if (user && bcrypt.compareSync(req.body.password, user.passwordHash)) {
      const token = jwt.sign(
        {
          userID: user._id,
          isAdmin: user.isAdmin,
        },
        secret,
        { expiresIn: "1d" }
      );
      return res.status(200).json({ token, ...user._doc }); // Return the token response
    } else {
      return res.status(400).json({ error: "Password is mismatch" }); // Return the mismatch password response
    }
  } catch (e) {
    return res.status(500).json({ message: e.message });
  }
});

router.get("/get/count", async (req, res) => {
  const userCount = await User.countDocuments((count) => count);
  if (!userCount) {
    res.status(500), json({ success: false });
  }
  res.status(200).send({
    userCount: userCount,
  });
});

module.exports = router;
