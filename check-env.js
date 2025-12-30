require('dotenv').config();

console.log("PORT:", process.env.PORT);
console.log("DATABASE_URL:", process.env.DATABASE_URL);
console.log("JWT_SECRET:", process.env.JWT_SECRET);
console.log("PAYSTACK_SECRET_KEY:", process.env.PAYSTACK_SECRET_KEY);
console.log("FLUTTERWAVE_SECRET_KEY:", process.env.FLUTTERWAVE_SECRET_KEY);
