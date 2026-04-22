const mongoose = require('mongoose');

const categories = [
  'Garbage / Waste not collected',
  'Broken streetlight',
  'Road pothole or damage',
  'Water supply issue',
  'Drainage / Sewage overflow',
  'Illegal construction',
  'Stray animal problem',
  'Noise complaint',
  'Public property damage',
  'Tree fallen / dangerous tree',
  'Flooding / waterlogging',
  'Other'
];

const statusValues = ['submitted', 'received', 'assigned', 'in_progress', 'resolved', 'closed'];

const counterSchema = new mongoose.Schema(
  {
    _id: {
      type: String,
      required: true
    },
    seq: {
      type: Number,
      default: 0
    }
  },
  { versionKey: false }
);

const Counter = mongoose.models.Counter || mongoose.model('Counter', counterSchema);

const statusTimelineSchema = new mongoose.Schema(
  {
    status: String,
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    updatedByName: String,
    note: String,
    timestamp: {
      type: Date,
      default: Date.now
    }
  },
  { _id: false }
);

const complaintSchema = new mongoose.Schema({
  complaintId: {
    type: String,
    unique: true
  },
  citizen: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  category: {
    type: String,
    enum: categories,
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  photos: [
    {
      type: String
    }
  ],
  location: {
    address: {
      type: String,
      required: true,
      trim: true
    },
    ward: {
      type: String,
      required: true,
      trim: true
    },
    landmark: {
      type: String,
      trim: true
    },
    coordinates: {
      lat: {
        type: Number
      },
      lng: {
        type: Number
      }
    }
  },
  status: {
    type: String,
    enum: statusValues,
    default: 'submitted'
  },
  statusTimeline: [statusTimelineSchema],
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  upvotes: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  ],
  upvoteCount: {
    type: Number,
    default: 0
  },
  resolutionPhoto: {
    type: String
  },
  resolutionNote: {
    type: String
  },
  submittedAt: {
    type: Date,
    default: Date.now
  },
  resolvedAt: {
    type: Date
  },
  isPublic: {
    type: Boolean,
    default: true
  }
});

complaintSchema.pre('validate', async function setComplaintId(next) {
  try {
    if (!this.complaintId) {
      const currentYear = new Date().getFullYear();
      const counterId = `complaint_${currentYear}`;

      const counter = await Counter.findOneAndUpdate(
        { _id: counterId },
        { $inc: { seq: 1 } },
        { new: true, upsert: true }
      );

      const sequenceNumber = String(counter.seq).padStart(5, '0');
      this.complaintId = `NS-${currentYear}-${sequenceNumber}`;
    }

    next();
  } catch (error) {
    next(error);
  }
});

complaintSchema.pre('save', function initializeTimeline(next) {
  if (this.isNew && (!this.statusTimeline || this.statusTimeline.length === 0)) {
    this.statusTimeline = [
      {
        status: 'submitted',
        updatedBy: this.citizen,
        updatedByName: 'Citizen',
        note: 'Complaint submitted by citizen',
        timestamp: new Date()
      }
    ];
  }

  this.upvoteCount = Array.isArray(this.upvotes) ? this.upvotes.length : 0;
  next();
});

module.exports = mongoose.model('Complaint', complaintSchema);
