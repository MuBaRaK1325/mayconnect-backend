import express from 'express';
import pool from '../db.js';

const router = express.Router();

// POST /data/purchases - Buy a plan
router.post('/', async (req, res) => {
  try {
    const { plan_id, username } = req.body;

    if (!plan_id || !username) {
      return res.status(400).json({ error: 'plan_id and username are required' });
    }

    const result = await pool.query(
      'INSERT INTO purchases (plan_id, username, purchased_at) VALUES ($1, $2, NOW()) RETURNING *',
      [plan_id, username]
    );

    res.json({ message: 'Purchase successful!', purchase: result.rows[0] });

  } catch (err) {
    console.error('🔥 FULL DATABASE ERROR:', err); // now logs full details
    res.status(500).json({ error: err.message });
  }
});

// GET /data/purchases/:username - Fetch purchase history
router.get('/:username', async (req, res) => {
  try {
    const { username } = req.params;

    const result = await pool.query(
      'SELECT p.id, p.plan_id, pl.name AS plan_name, pl.network, pl.size, pl.price, p.purchased_at ' +
      'FROM purchases p ' +
      'JOIN plans pl ON p.plan_id = pl.id ' +
      'WHERE p.username = $1',
      [username]
    );

    res.json(result.rows);

  } catch (err) {
    console.error('🔥 FULL DATABASE ERROR:', err);
    res.status(500).json({ error: err.message });
  }
});

export default router;
