/* ============================================================
   MAYCONNECT BUY DATA ROUTE
   ------------------------------------------------------------
   - Completely separate from normal /api/buy-data
   - ONLY company = mayconnect
   - PENDING = NO wallet debit
   - FAILED = NO wallet debit
   - SUCCESS = wallet debit
   - CASHBACK ONLY for Mayconnect
   - ₦10 cashback
   - Maximum 5 cashback credits per Lagos day
   ============================================================ */

const express = require("express");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");


function configureMayconnectBuyData(config) {

  const {
    pool,
    auth,
    buyDataLimiter,

    callMaitamaData,
    callCheapDataHubData,
    callSubPadiData,
    callArrahuzData,
    callJJDataSubData,
    callAlihsanData,

    getCompanyAdmin,
    sendWalletUpdate,
    sendPushNotification
  } = config;


  /* ============================================================
     VALIDATE REQUIRED DEPENDENCIES
     ============================================================ */

  if (!pool) {
    throw new Error("Mayconnect buy-data: pool is missing");
  }

  if (typeof auth !== "function") {
    throw new Error("Mayconnect buy-data: auth middleware is missing");
  }

  if (typeof buyDataLimiter !== "function") {
    throw new Error("Mayconnect buy-data: buyDataLimiter is missing");
  }

  if (typeof callMaitamaData !== "function") {
    throw new Error("Mayconnect buy-data: callMaitamaData is missing");
  }

  if (typeof callCheapDataHubData !== "function") {
    throw new Error("Mayconnect buy-data: callCheapDataHubData is missing");
  }

  if (typeof callSubPadiData !== "function") {
    throw new Error("Mayconnect buy-data: callSubPadiData is missing");
  }

  if (typeof callArrahuzData !== "function") {
    throw new Error("Mayconnect buy-data: callArrahuzData is missing");
  }

  if (typeof callJJDataSubData !== "function") {
    throw new Error("Mayconnect buy-data: callJJDataSubData is missing");
  }

  if (typeof callAlihsanData !== "function") {
    throw new Error("Mayconnect buy-data: callAlihsanData is missing");
  }

  if (typeof getCompanyAdmin !== "function") {
    throw new Error("Mayconnect buy-data: getCompanyAdmin is missing");
  }

  if (typeof sendWalletUpdate !== "function") {
    throw new Error("Mayconnect buy-data: sendWalletUpdate is missing");
  }

  if (typeof sendPushNotification !== "function") {
    throw new Error("Mayconnect buy-data: sendPushNotification is missing");
  }


  /* ============================================================
     CREATE ROUTER ONLY AFTER CONFIGURATION
     ============================================================ */

  const router = express.Router();


  /* ============================================================
     MAYCONNECT BUY DATA
     ============================================================ */

  router.post(
    "/api/mayconnect/buy-data",
    auth,
    buyDataLimiter,

    async (req, res) => {

      const client = await pool.connect();

      let transactionStarted = false;

      try {

        const {
          plan_id,
          phone,
          pin
        } = req.body;


        /* ======================================================
           BASIC VALIDATION
           ====================================================== */

        if (!plan_id || !phone) {

          return res.status(400).json({
            message: "plan_id and phone are required"
          });

        }


        if (!/^\d{10,15}$/.test(String(phone))) {

          return res.status(400).json({
            message:
              "Invalid phone number. Use 11 digits like 08101234567"
          });

        }


        /* ======================================================
           BEGIN DB TRANSACTION
           ====================================================== */

        await client.query("BEGIN");
        transactionStarted = true;


        /* ======================================================
           LOAD USER
           ====================================================== */

        const userRes = await client.query(
          `
          SELECT *
          FROM users
          WHERE id=$1
          FOR UPDATE
          `,
          [req.user.id]
        );


        const user = userRes.rows[0];


        if (!user) {

          await client.query("ROLLBACK");
          transactionStarted = false;

          return res.status(404).json({
            message: "User not found"
          });

        }


        /* ======================================================
           MAYCONNECT ONLY
           ====================================================== */

        const companyKey =
          String(user.company || "")
            .trim()
            .toLowerCase();


        if (companyKey !== "mayconnect") {

          await client.query("ROLLBACK");
          transactionStarted = false;

          return res.status(403).json({
            message:
              "This purchase route is only available to Mayconnect users."
          });

        }


        /* ======================================================
           PIN / BIOMETRIC
           ====================================================== */

        if (pin !== "biometric_verified") {

          if (!user.pin) {

            await client.query("ROLLBACK");
            transactionStarted = false;

            return res.status(400).json({
              message:
                "Transaction PIN not set. Please set your PIN in Profile first.",
              needPin: true
            });

          }


          const validPin =
            await bcrypt.compare(
              String(pin),
              String(user.pin)
            );


          if (!validPin) {

            await client.query("ROLLBACK");
            transactionStarted = false;

            return res.status(400).json({
              message: "Invalid PIN"
            });

          }

        }


        /* ======================================================
           LOAD PLAN
           ====================================================== */

        const planRes = await client.query(
          `
          SELECT *
          FROM plans
          WHERE id=$1
            AND is_active=TRUE
          `,
          [plan_id]
        );


        if (!planRes.rows.length) {

          await client.query("ROLLBACK");
          transactionStarted = false;

          return res.status(400).json({
            message: "Plan not found or inactive"
          });

        }


        const plan = planRes.rows[0];


        /* ======================================================
           PLAN RESTRICTION
           ====================================================== */

        if (
          plan.restricted &&
          String(plan.company || "").toLowerCase() !==
            String(user.company || "").toLowerCase()
        ) {

          await client.query("ROLLBACK");
          transactionStarted = false;

          return res.status(403).json({
            message:
              "Plan restricted to company users"
          });

        }


        /* ======================================================
           PROVIDER VALIDATION
           ====================================================== */

        if (!plan.provider) {

          await client.query("ROLLBACK");
          transactionStarted = false;

          return res.status(400).json({
            message:
              "Plan not configured with provider. Contact admin."
          });

        }


        if (plan.provider === "subpadi") {

          if (!plan.api_plan_id) {

            await client.query("ROLLBACK");
            transactionStarted = false;

            return res.status(400).json({
              message:
                "Plan not configured with product_id. Contact admin."
            });

          }

        } else {

          if (
            !plan.api_plan_id ||
            plan.network_id === null ||
            plan.network_id === undefined
          ) {

            await client.query("ROLLBACK");
            transactionStarted = false;

            return res.status(400).json({
              message:
                "Plan not configured with provider plan ID or network_id. Contact admin."
            });

          }


          const netId =
            Number(plan.network_id);


          if (
            !Number.isFinite(netId) ||
            netId < 1 ||
            netId > 4
          ) {

            await client.query("ROLLBACK");
            transactionStarted = false;

            return res.status(400).json({
              message:
                `Invalid network_id: ${plan.network_id}. Must be numeric 1-4`
            });

          }

        }


        /* ======================================================
           USER TIER / PRICE
           ====================================================== */

        const tierRes = await client.query(
          `
          SELECT 1
          FROM top_users
          WHERE id=$1
          `,
          [user.id]
        );


        const isTopUser =
          tierRes.rows.length > 0;


        const price =
          isTopUser
            ? (plan.top_price || plan.price)
            : plan.price;


        const priceNum =
          Number(price);


        const cost =
          Number(plan.cost);


        if (
          !Number.isFinite(priceNum) ||
          priceNum <= 0
        ) {

          await client.query("ROLLBACK");
          transactionStarted = false;

          return res.status(400).json({
            message:
              "Invalid plan price. Contact admin."
          });

        }


        if (
          !Number.isFinite(cost) ||
          cost < 0
        ) {

          await client.query("ROLLBACK");
          transactionStarted = false;

          return res.status(400).json({
            message:
              "Invalid plan cost. Contact admin."
          });

        }


        /* ======================================================
           BALANCE CHECK
           ------------------------------------------------------
           IMPORTANT:
           NO DEBIT YET.
           ====================================================== */

        const balanceBefore =
          Number(user.wallet_balance);


        if (
          !Number.isFinite(balanceBefore) ||
          balanceBefore < priceNum
        ) {

          await client.query("ROLLBACK");
          transactionStarted = false;

          return res.status(400).json({
            message:
              `Insufficient balance. You have ₦${balanceBefore.toFixed(
                2
              )}, this plan costs ₦${priceNum.toFixed(2)}`
          });

        }


        /* ======================================================
           CREATE PENDING TRANSACTION
           ------------------------------------------------------
           IMPORTANT:
           WALLET IS NOT DEBITED.
           ====================================================== */

        const ref =
          "MC-DATA-" + uuidv4();


        const txRes = await client.query(
          `
          INSERT INTO transactions(
            user_id,
            plan_id,
            type,
            amount,
            cost,
            phone,
            network,
            reference,
            status,
            plan_name,
            provider,
            balance_before,
            balance_after
          )
          VALUES(
            $1,
            $2,
            'DATA',
            $3::numeric,
            $4::numeric,
            $5,
            $6,
            $7,
            'PENDING',
            $8,
            $9,
            $10::numeric,
            $11::numeric
          )
          RETURNING id
          `,
          [
            user.id,
            plan.id,
            priceNum,
            cost,
            phone,
            plan.network,
            ref,
            plan.name,
            plan.provider,
            balanceBefore,
            balanceBefore
          ]
        );


        const txId =
          txRes.rows[0].id;


        await client.query("COMMIT");
        transactionStarted = false;


        /* ======================================================
           CALL PROVIDER
           ====================================================== */

        let apiResponse = null;

        let finalStatus =
          "FAILED";

        let responseMsg =
          "Unknown error";


        try {

          if (plan.provider === "maitama") {

            apiResponse =
              await callMaitamaData(
                phone,
                plan.network_id,
                plan.api_plan_id,
                user.company
              );

          }

          else if (plan.provider === "cheapdatahub") {

            apiResponse =
              await callCheapDataHubData(
                phone,
                plan.network_id,
                plan.api_plan_id
              );

          }

          else if (plan.provider === "subpadi") {

            apiResponse =
              await callSubPadiData(
                phone,
                plan.api_plan_id,
                user.company
              );

          }

          else if (plan.provider === "arrahuz") {

            apiResponse =
              await callArrahuzData(
                phone,
                plan.network_id,
                plan.api_plan_id,
                user.company
              );

          }

          else if (plan.provider === "jjdatasub") {

            apiResponse =
              await callJJDataSubData(
                phone,
                plan.network_id,
                plan.api_plan_id,
                user.company
              );

          }

          else if (plan.provider === "alihsandatasub") {

            apiResponse =
              await callAlihsanData(
                phone,
                plan.network_id,
                plan.api_plan_id,
                user.company
              );

          }

          else {

            throw new Error("Unknown provider");

          }


          /* ====================================================
             NORMALIZE PROVIDER RESPONSE
             ==================================================== */

          const rawStatus =
            apiResponse?.status ??
            apiResponse?.Status ??
            apiResponse?.data?.status ??
            apiResponse?.data?.Status ??
            apiResponse?.data?.data?.status ??
            apiResponse?.data?.data?.Status ??
            null;


          const normalizedStatus =
            String(rawStatus ?? "")
              .trim()
              .toLowerCase();


          const providerCode =
            apiResponse?.code ??
            apiResponse?.status_code ??
            apiResponse?.statusCode ??
            apiResponse?.data?.code ??
            apiResponse?.data?.status_code ??
            apiResponse?.data?.statusCode ??
            null;


          const successFlag =
            apiResponse?.success === true ||
            apiResponse?.data?.success === true ||
            apiResponse?.data?.data?.success === true;


          const providerMessage =
            apiResponse?.message ??
            apiResponse?.msg ??
            apiResponse?.response_msg ??
            apiResponse?.data?.message ??
            apiResponse?.data?.msg ??
            apiResponse?.data?.response_msg ??
            apiResponse?.api_response ??
            "";


          const normalizedMessage =
            String(providerMessage)
              .trim()
              .toLowerCase();


          console.log(
            "========== MAYCONNECT DATA STATUS =========="
          );

          console.log({
            company: user.company,
            provider: plan.provider,
            reference: ref,
            rawStatus,
            normalizedStatus,
            providerCode,
            successFlag,
            providerMessage
          });

          console.log(
            "RAW PROVIDER RESPONSE:",
            apiResponse
          );

          console.log(
            "============================================"
          );


          /* ====================================================
             SUCCESS
             ==================================================== */

          const isSuccessful =
            normalizedStatus === "success" ||
            normalizedStatus === "successful" ||
            normalizedStatus === "completed" ||
            normalizedStatus === "complete" ||
            normalizedStatus === "delivered" ||
            providerCode === 200 ||
            successFlag === true ||
            (
              normalizedStatus === "true" &&
              (
                normalizedMessage.includes("success") ||
                normalizedMessage.includes("successful") ||
                normalizedMessage.includes("delivered") ||
                normalizedMessage.includes("completed")
              )
            );


          /* ====================================================
             PENDING
             ==================================================== */

          const isPending =
            normalizedStatus === "pending" ||
            normalizedStatus === "processing" ||
            normalizedStatus === "queued" ||
            normalizedStatus === "initiated" ||
            normalizedStatus === "in_progress";


          if (isSuccessful) {

            finalStatus =
              "SUCCESS";

            responseMsg =
              "Transaction successful";

          }

          else if (isPending) {

            finalStatus =
              "PENDING";

            responseMsg =
              "Transaction pending. Will be delivered shortly.";

          }

          else {

            finalStatus =
              "FAILED";

            responseMsg =
              providerMessage ||
              "Provider rejected transaction";

          }

        }

        catch (vtuErr) {

          finalStatus =
            "FAILED";


          responseMsg =
            vtuErr.response?.data?.message ||
            vtuErr.response?.data?.api_response ||
            vtuErr.message ||
            "API timeout";


          apiResponse =
            vtuErr.response?.data ||
            {
              error: vtuErr.message
            };


          if (
            vtuErr.response?.data?.errors
          ) {

            const errs =
              vtuErr.response.data.errors;


            if (errs.network) {

              responseMsg =
                `Network error: ${errs.network[0]}`;

            }

            else if (errs.plan) {

              responseMsg =
                `Plan error: ${errs.plan[0]}`;

            }

            else if (errs.mobile_number) {

              responseMsg =
                `Phone error: ${errs.mobile_number[0]}`;

            }

          }


          /* ====================================================
             TIMEOUT
             ----------------------------------------------------
             Treat possible-success timeout as PENDING.
             NO WALLET DEBIT.
             ==================================================== */

          if (
            vtuErr.message ===
              "TIMEOUT_POSSIBLE_SUCCESS" ||
            vtuErr.code ===
              "ECONNABORTED"
          ) {

            finalStatus =
              "PENDING";

            responseMsg =
              "Request submitted. Delivery pending.";

          }

        }


        /* ======================================================
           FINALIZE PENDING
           ------------------------------------------------------
           NO WALLET DEBIT
           ====================================================== */

        if (
          finalStatus === "PENDING"
        ) {

          await client.query("BEGIN");
          transactionStarted = true;


          await client.query(
            `
            UPDATE transactions
            SET
              status='PENDING',
              response_msg=$1,
              api_response=$2,
              updated_at=NOW(),
              balance_after=balance_before
            WHERE id=$3
            `,
            [
              responseMsg,
              JSON.stringify(apiResponse),
              txId
            ]
          );


          await client.query("COMMIT");
          transactionStarted = false;


          sendWalletUpdate(
            user.id,
            balanceBefore
          );


          await sendPushNotification(
            user.company,
            user.id,
            {
              title:
                "MAYCONNECT - Data Purchase",

              body:
                `Your ${plan.name} purchase for ${phone} is pending.`,

              url:
                "/dashboard.html"
            }
          );


          return res.json({

            success: true,

            reference:
              ref,

            status:
              "PENDING",

            balance:
              Number(balanceBefore),

            balance_before:
              Number(balanceBefore),

            balance_after:
              Number(balanceBefore),

            tier:
              isTopUser
                ? "top"
                : "default",

            phone:
              phone,

            network:
              plan.network,

            plan_name:
              plan.name,

            amount:
              Number(priceNum),

            cashback:
              0,

            cashback_credited:
              false,

            message:
              responseMsg,

            created_at:
              new Date().toISOString()

          });

        }


        /* ======================================================
           FINALIZE FAILED
           ------------------------------------------------------
           NO WALLET DEBIT
           ====================================================== */

        if (
          finalStatus === "FAILED"
        ) {

          await client.query("BEGIN");
          transactionStarted = true;


          await client.query(
            `
            UPDATE transactions
            SET
              status='FAILED',
              response_msg=$1,
              api_response=$2,
              updated_at=NOW(),
              balance_after=balance_before
            WHERE id=$3
            `,
            [
              responseMsg,
              JSON.stringify(apiResponse),
              txId
            ]
          );


          await client.query("COMMIT");
          transactionStarted = false;


          sendWalletUpdate(
            user.id,
            balanceBefore
          );


          return res.status(400).json({

            success: false,

            message:
              responseMsg,

            reference:
              ref,

            status:
              "FAILED",

            balance_before:
              Number(balanceBefore),

            balance_after:
              Number(balanceBefore),

            phone:
              phone,

            network:
              plan.network,

            plan_name:
              plan.name,

            amount:
              Number(priceNum),

            cashback:
              0,

            cashback_credited:
              false,

            created_at:
              new Date().toISOString()

          });

        }


        /* ======================================================
           SUCCESS
           ------------------------------------------------------
           NOW WE DEBIT.
           ====================================================== */

        await client.query("BEGIN");
        transactionStarted = true;


        /* ======================================================
           LOCK WALLET AGAIN
           ====================================================== */

        const lockedUserRes =
          await client.query(
            `
            SELECT wallet_balance
            FROM users
            WHERE id=$1
            FOR UPDATE
            `,
            [user.id]
          );


        if (!lockedUserRes.rows.length) {

          await client.query("ROLLBACK");
          transactionStarted = false;

          return res.status(500).json({
            message:
              "User wallet could not be loaded."
          });

        }


        const currentBalance =
          Number(
            lockedUserRes.rows[0].wallet_balance
          );


        /* ======================================================
           IMPORTANT SUCCESS SAFETY CHECK
           ====================================================== */

        if (
          !Number.isFinite(currentBalance) ||
          currentBalance < priceNum
        ) {

          await client.query(
            `
            UPDATE transactions
            SET
              status='PENDING',
              response_msg=$1,
              api_response=$2,
              updated_at=NOW(),
              balance_after=$3::numeric
            WHERE id=$4
            `,
            [
              "Provider successful, but wallet balance is insufficient for debit. Manual reconciliation required.",
              JSON.stringify(apiResponse),
              currentBalance,
              txId
            ]
          );


          await client.query("COMMIT");
          transactionStarted = false;


          sendWalletUpdate(
            user.id,
            currentBalance
          );


          return res.status(409).json({

            success: false,

            reference:
              ref,

            status:
              "PENDING",

            message:
              "Transaction was successful at the provider, but the wallet balance is currently insufficient. Please contact support.",

            balance:
              currentBalance

          });

        }


        /* ======================================================
           DEBIT WALLET
           ====================================================== */

        const balanceAfterDeduct =
          currentBalance - priceNum;


        await client.query(
          `
          UPDATE users
          SET
            wallet_balance=$1::numeric,
            updated_at=NOW()
          WHERE id=$2
          `,
          [
            balanceAfterDeduct,
            user.id
          ]
        );


        let finalBalance =
          balanceAfterDeduct;


        /* ======================================================
           CASHBACK
           ------------------------------------------------------
           ONLY MAYCONNECT
           ====================================================== */

        const grossProfit =
          priceNum - cost;


        let cashbackAmount =
          0;


        let cashbackEligible =
          false;


        let cashbackCountToday =
          0;


        /* ======================================================
           CASHBACK RULE
           ------------------------------------------------------
           Profit must be at least ₦50
           AND maximum 5 credits per Lagos day.
           ====================================================== */

        if (
          companyKey === "mayconnect" &&
          grossProfit >= 50
        ) {

          const cashbackCountRes =
            await client.query(
              `
              SELECT COUNT(*)::integer AS count
              FROM transactions
              WHERE user_id=$1

                AND LOWER(
                  COALESCE(
                    metadata->>'cashback_company',
                    ''
                  )
                )='mayconnect'

                AND COALESCE(
                  metadata->>'cashback_credited',
                  'false'
                )='true'

                AND DATE(
                  created_at AT TIME ZONE 'Africa/Lagos'
                ) =
                DATE(
                  NOW() AT TIME ZONE 'Africa/Lagos'
                )
              `,
              [user.id]
            );


          cashbackCountToday =
            Number(
              cashbackCountRes.rows[0]?.count || 0
            );


          if (
            cashbackCountToday < 5
          ) {

            cashbackAmount =
              10;

            cashbackEligible =
              true;


            finalBalance =
              finalBalance +
              cashbackAmount;


            await client.query(
              `
              UPDATE users
              SET
                wallet_balance=$1::numeric,
                updated_at=NOW()
              WHERE id=$2
              `,
              [
                finalBalance,
                user.id
              ]
            );


            console.log(
              "MAYCONNECT CASHBACK CREDITED:",
              {
                user_id:
                  user.id,

                transaction_id:
                  txId,

                reference:
                  ref,

                cashback:
                  cashbackAmount,

                cashback_count_today:
                  cashbackCountToday + 1,

                gross_profit:
                  grossProfit,

                net_profit:
                  grossProfit -
                  cashbackAmount
              }
            );

          }

        }


        /* ======================================================
           NET PROFIT
           ====================================================== */

        const netProfit =
          Math.max(
            0,
            grossProfit -
            cashbackAmount
          );


        /* ======================================================
           ADMIN PROFIT
           ====================================================== */

        const adminId =
          await getCompanyAdmin(
            user.company
          );


        if (
          adminId &&
          netProfit > 0
        ) {

          await client.query(
            `
            UPDATE users
            SET
              admin_wallet =
                admin_wallet +
                $1::numeric,
              updated_at=NOW()
            WHERE id=$2
            `,
            [
              netProfit,
              adminId
            ]
          );


          await client.query(
            `
            INSERT INTO profits(
              transaction_id,
              type,
              amount,
              reference,
              credited_to_user_id
            )
            VALUES(
              $1,
              'sale',
              $2::numeric,
              $3,
              $4
            )
            `,
            [
              txId,
              netProfit,
              ref,
              adminId
            ]
          );

        }


        /* ======================================================
           RECORD CASHBACK METADATA
           ====================================================== */

        await client.query(
          `
          UPDATE transactions
          SET
            metadata =
              COALESCE(
                metadata,
                '{}'::jsonb
              )
              ||
              jsonb_build_object(

                'cashback_credited',
                $1::boolean,

                'cashback_company',
                'mayconnect',

                'cashback_amount',
                $2::numeric,

                'cashback_count_today',
                $3::integer,

                'gross_profit',
                $4::numeric,

                'net_profit',
                $5::numeric

              )
          WHERE id=$6
          `,
          [
            cashbackEligible,
            cashbackAmount,

            cashbackEligible
              ? cashbackCountToday + 1
              : cashbackCountToday,

            grossProfit,
            netProfit,

            txId
          ]
        );


        /* ======================================================
           FINAL TRANSACTION UPDATE
           ====================================================== */

        await client.query(
          `
          UPDATE transactions
          SET
            status='SUCCESS',
            response_msg=$1,
            api_response=$2,
            updated_at=NOW(),
            balance_after=$3::numeric
          WHERE id=$4
          `,
          [
            "Transaction successful",
            JSON.stringify(apiResponse),
            finalBalance,
            txId
          ]
        );


        await client.query("COMMIT");
        transactionStarted = false;


        /* ======================================================
           WALLET UPDATE
           ====================================================== */

        sendWalletUpdate(
          user.id,
          finalBalance
        );


        /* ======================================================
           PUSH NOTIFICATION
           ====================================================== */

        await sendPushNotification(
          user.company,
          user.id,
          {
            title:
              "MAYCONNECT - Data Purchase",

            body:
              `Your ${plan.name} purchase for ${phone} was successful.`,

            url:
              "/dashboard.html"
          }
        );


        /* ======================================================
           SUCCESS RESPONSE
           ====================================================== */

        return res.json({

          success: true,

          reference:
            ref,

          status:
            "SUCCESS",

          balance:
            Number(finalBalance),

          balance_before:
            Number(balanceBefore),

          balance_after:
            Number(finalBalance),

          tier:
            isTopUser
              ? "top"
              : "default",

          phone:
            phone,

          network:
            plan.network,

          plan_name:
            plan.name,

          amount:
            Number(priceNum),

          cashback:
            Number(cashbackAmount),

          cashback_credited:
            cashbackEligible,

          created_at:
            new Date().toISOString()

        });

      }

      catch (e) {

        if (transactionStarted) {

          try {
            await client.query("ROLLBACK");
          } catch (_) {}

        }


        console.error(
          "MAYCONNECT BUY DATA ERROR:",
          e
        );


        return res.status(500).json({
          message:
            "Purchase failed. Try again later."
        });

      }

      finally {

        client.release();

      }

    }
  );


  /* ============================================================
     RETURN CONFIGURED ROUTER
     ============================================================ */

  return router;
}


module.exports = {
  configureMayconnectBuyData
};