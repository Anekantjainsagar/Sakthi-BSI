# User Guide - Data Completeness & Delete Features

## 🎯 Quick Overview

Two new features have been added to help you manage your domain analysis data:

1. **📊 Data Completeness Check** - See what data is stored vs. displayed
2. **🗑️ Delete Data** - Remove all cached data for a domain

---

## 📊 Data Completeness Check

### What It Does
Shows you exactly what data is stored in the database and what's being displayed in the UI.

### Where to Find It
After running an analysis, scroll down to the results section and look for:
```
📊 Data Completeness Check
```
Click to expand it.

### What You'll See

#### Overall Metrics
```
Completeness: 95%
Phases Displayed: 5/5
Missing: 0
Incomplete: 1
```

#### Phase Details
For each phase (Business, Infrastructure, Application, Vulnerabilities, Risk):
- Status: ✅ COMPLETE, ⚠️ INCOMPLETE, or ❌ MISSING
- Stored Records: How many records are in the database
- Displayed Records: How many records are shown in the UI
- Missing Keys: What data fields are not displayed

### Example Report

```
✅ Phase 1: Business Domain [COMPLETE]
   Stored Records: 250
   Displayed Records: 250
   Missing Keys: None

⚠️ Phase 3: Application Landscape [INCOMPLETE]
   Stored Records: 150
   Displayed Records: 145
   Missing Keys: ssl_certificates, security_headers
```

### What to Do If Data Is Incomplete

**Option 1: Check the Missing Fields**
- Look at the "Missing Keys" section
- These are data fields stored but not displayed
- This might be a UI display issue

**Option 2: Re-run the Analysis**
- Delete the data (see below)
- Run the analysis again
- This will refresh all data

**Option 3: Contact Support**
- If data is consistently incomplete
- Provide the missing keys list
- Include the domain name

---

## 🗑️ Delete Data

### What It Does
Permanently deletes ALL cached data for a domain, including:
- Analysis history
- All 5 phase results
- API cache entries
- Search history records

### Where to Find It
In the results section, look for the button in the top right:
```
🗑️ Delete Data
```

### How to Use It

#### Step 1: Click the Delete Button
```
Results Header
├─ Analysis Results — example.com
└─ [🗑️ Delete Data] ← Click here
```

#### Step 2: Review the Confirmation Dialog
```
⚠️ DELETE CONFIRMATION

You are about to permanently delete ALL cached data for example.com:
- Analysis history
- All 5 phase results
- API cache
- Search history

This action CANNOT be undone.
```

#### Step 3: Confirm or Cancel
```
[🗑️ Yes, Delete Everything]  [❌ Cancel]
```

#### Step 4: Confirmation
```
✅ Successfully deleted all data for example.com
```

### Important Notes

⚠️ **This action CANNOT be undone**
- Once deleted, the data is gone forever
- You'll need to re-run the analysis to get the data back
- Make sure you want to delete before confirming

✅ **What happens after deletion**
- All data is removed from the database
- The UI clears and returns to the home screen
- You can search for the domain again
- You can re-run the analysis from scratch

---

## 📋 Common Scenarios

### Scenario 1: Checking Data Completeness

**You want to know if all data is being displayed**

1. Run an analysis for your domain
2. Scroll to the results section
3. Click "📊 Data Completeness Check"
4. Check the completeness percentage
5. If 100%, all data is displayed
6. If less than 100%, see what's missing

### Scenario 2: Deleting Old Data

**You want to delete cached data to free up space**

1. Find the domain in your search history
2. Click on it to load the results
3. Click "🗑️ Delete Data" button
4. Confirm the deletion
5. Data is deleted
6. You can re-run the analysis later

### Scenario 3: Re-running an Analysis

**You want to get fresh data for a domain**

1. Load the existing analysis
2. Click "🗑️ Delete Data"
3. Confirm deletion
4. Go back to home screen
5. Enter the domain name again
6. Click "🚀 Start Analysis"
7. Fresh analysis will run

### Scenario 4: Investigating Missing Data

**You notice some data is missing**

1. Click "📊 Data Completeness Check"
2. Look at the "Missing Keys" section
3. Note which fields are missing
4. Check if they're important for your analysis
5. If critical, delete and re-run the analysis

---

## 🎨 UI Elements

### Delete Button
```
Location: Top right of results header
Label: 🗑️ Delete Data
Color: Gray (secondary)
Size: Full width
```

### Completeness Check Expander
```
Location: Below results header
Label: 📊 Data Completeness Check
Type: Expandable/collapsible
Content: Metrics and phase details
```

### Confirmation Dialog
```
Type: Warning dialog
Title: ⚠️ DELETE CONFIRMATION
Content: Warning message + what will be deleted
Buttons: Confirm (red) and Cancel (gray)
```

---

## 📊 Understanding the Metrics

### Completeness Percentage
```
0-25%:   Very incomplete - Most data missing
25-50%:  Incomplete - Significant data missing
50-75%:  Partially complete - Some data missing
75-99%:  Nearly complete - Minor data missing
100%:    Complete - All data displayed
```

### Phases Displayed
```
5/5:  All phases are displayed
4/5:  One phase is missing
3/5:  Two phases are missing
etc.
```

### Status Indicators
```
✅ COMPLETE:    All data for this phase is displayed
⚠️  INCOMPLETE: Some data for this phase is missing
❌ MISSING:     This phase has data but is not displayed
```

---

## ⚠️ Important Warnings

### Before Deleting Data

1. **Make sure you want to delete**
   - This action cannot be undone
   - You'll need to re-run the analysis to get the data back

2. **Check if you need the data**
   - Export reports if needed
   - Save important findings
   - Document any insights

3. **Consider the time**
   - Re-running analysis takes time
   - Plan accordingly
   - Don't delete if you need quick access

### After Deleting Data

1. **Data is gone**
   - Cannot be recovered
   - Must re-run analysis to get it back

2. **Search history is cleared**
   - Domain won't appear in recent searches
   - You can search for it again

3. **Cache is cleared**
   - API responses are deleted
   - Fresh API calls will be made on re-run

---

## 🔍 Troubleshooting

### Issue: Completeness shows 0%
**Solution**: 
- Ensure analysis has completed
- Check if data was saved to database
- Try refreshing the page

### Issue: Delete button not working
**Solution**:
- Check database permissions
- Ensure domain exists in database
- Try refreshing the page

### Issue: Missing phases not showing
**Solution**:
- Run completeness check again
- Refresh the page
- Check browser console for errors

### Issue: Confirmation dialog not appearing
**Solution**:
- Clear browser cache
- Reload the page
- Try a different browser

### Issue: Data not deleted
**Solution**:
- Check database permissions
- Verify domain name is correct
- Check database logs for errors

---

## 💡 Tips & Tricks

### Tip 1: Regular Cleanup
- Delete old analyses periodically
- Keeps database clean
- Improves performance

### Tip 2: Check Before Deleting
- Always check completeness first
- Make sure you have all the data you need
- Export reports if needed

### Tip 3: Re-run for Fresh Data
- Delete and re-run for latest information
- Useful for monitoring changes
- Gets fresh API data

### Tip 4: Use Search History
- Search history shows completion status
- Helps identify which analyses are complete
- Easier to find domains to delete

---

## 📞 Support

### Getting Help

**For questions about completeness check:**
- Read the detailed guide: `DATA_COMPLETENESS_AND_DELETE.md`
- Check the phase details
- Look at missing keys

**For questions about delete feature:**
- Review the confirmation dialog
- Check the warning message
- Read the user guide

**For technical issues:**
- Check browser console for errors
- Verify database permissions
- Check database logs

---

## 🎓 Learning More

### Detailed Documentation
- `DATA_COMPLETENESS_AND_DELETE.md` - Complete guide
- `FEATURE_SUMMARY.md` - Quick reference
- Code docstrings - Technical details

### Examples
- See documentation for code examples
- Check troubleshooting section
- Review common scenarios

---

## ✅ Checklist

Before deleting data, make sure:
- [ ] You've reviewed the completeness check
- [ ] You've exported any important reports
- [ ] You've documented important findings
- [ ] You understand the data will be deleted
- [ ] You're ready to re-run the analysis if needed

---

## Summary

### Data Completeness Check
✅ Shows what data is stored vs. displayed
✅ Identifies missing/incomplete data
✅ Helps ensure data quality
✅ No action required

### Delete Data
✅ Removes all cached data for a domain
✅ Requires confirmation
✅ Cannot be undone
✅ Allows fresh analysis

---

**Ready to use these features? Start with the completeness check to see your data status!**
