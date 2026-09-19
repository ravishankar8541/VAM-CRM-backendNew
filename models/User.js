const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const slabSchema = new mongoose.Schema({
  minPercent: { type: Number, required: true, default: 0 },
  maxPercent: { type: Number, required: true, default: 9999 },
  rate: { type: Number, required: true, default: 0 },
  name: { type: String, default: '' },
  color: { type: String, default: 'orange' }
}, { _id: false });

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
      select: false,
    },
    role: {
      type: String,
      enum: ['admin', 'hr', 'employee', 'sales'],
      default: 'employee',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    // Quotas & Targets
    targetTotal: {
      type: Number,
      default: 250000,
    },
    targetCore: {
      type: Number,
      default: 175000,
    },
    targetGoogleAds: {
      type: Number,
      default: 75000,
    },
    // Commission Calculation Basis
    calculationBasis: {
      type: String,
      enum: ['totalSales', 'paidAmount'],
      default: 'totalSales'
    },
    // Gatekeeper Qualification Rules
    gatekeeperEnabled: {
      type: Boolean,
      default: true
    },
    gatekeeperMinCore: {
      type: Number,
      default: 100
    },
    // Milestone Flat Cash Bonus
    flatBonus: {
      type: Number,
      default: 0
    },
    bonusMinPercent: {
      type: Number,
      default: 100
    },
    // Custom Slabs (Tier Configuration)
    customSlabs: {
      type: [slabSchema],
      default: [
        { minPercent: 70, maxPercent: 99, rate: 4, name: 'On Track', color: 'amber' },
        { minPercent: 100, maxPercent: 149, rate: 6, name: 'Target Achieved', color: 'green' },
        { minPercent: 150, maxPercent: 199, rate: 8, name: 'Star Performer', color: 'blue' },
        { minPercent: 200, maxPercent: 9999, rate: 10, name: 'Elite Club', color: 'emerald' }
      ]
    },
    lastLogin: {
      type: Date,
      default: null,
    },
    resetPasswordToken: {
      type: String,
      default: null,
    },
    resetPasswordExpires: {
      type: Date,
      default: null,
    },
    lastPasswordChange: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

userSchema.pre('save', async function () {
  if (!this.isModified('password')) return;
  this.password = await bcrypt.hash(this.password, 12);
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);