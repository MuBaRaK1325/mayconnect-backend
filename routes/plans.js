import express from 'express';
import pool from '../db.js';

const router = express.Router();

router.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM plans');
    res.json(result.rows);
  } catch (err) {
    console.error('Exact DB error:', err); // <- change here to log full error
    res.status(500).json({ error: 'Database error' });
  }
});

export default router;
